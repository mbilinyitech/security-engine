//! Path tracer with global illumination and JSON scenes.
//!
//! Direct light plus cosine-weighted diffuse bounces, so colour bleeds and the
//! sky lights the room. Scenes are data: spheres, boxes, a ground plane, a light
//! and a camera, all in JSON. Deterministic per pixel, threaded by rows.

use serde_json::Value;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct V {
    x: f64,
    y: f64,
    z: f64,
}

impl V {
    fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }
    fn add(self, other: V) -> V {
        V::new(self.x + other.x, self.y + other.y, self.z + other.z)
    }
    fn sub(self, other: V) -> V {
        V::new(self.x - other.x, self.y - other.y, self.z - other.z)
    }
    fn mul(self, k: f64) -> V {
        V::new(self.x * k, self.y * k, self.z * k)
    }
    fn hadamard(self, other: V) -> V {
        V::new(self.x * other.x, self.y * other.y, self.z * other.z)
    }
    fn dot(self, other: V) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }
    fn len(self) -> f64 {
        self.dot(self).sqrt()
    }
    fn unit(self) -> V {
        self.mul(1.0 / self.len().max(1e-12))
    }
    fn cross(self, other: V) -> V {
        V::new(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x,
        )
    }
}

#[derive(Clone, Copy)]
struct Mat {
    albedo: V,
    specular: f64,
    shininess: f64,
    reflect: f64,
    metallic: f64,
    texture: u8,
}

#[derive(Clone, Copy)]
enum Shape {
    Sphere { centre: V, radius: f64 },
    Box { centre: V, half: f64 },
    Plane { y: f64 },
}

#[derive(Clone, Copy)]
struct Object {
    shape: Shape,
    mat: Mat,
}

struct Camera {
    origin: V,
    forward: V,
    right: V,
    up: V,
    field: f64,
    aspect: f64,
}

pub struct PathScene {
    width: usize,
    height: usize,
    samples: usize,
    threads: usize,
    bounces: usize,
    aperture: f64,
    exposure: f64,
    objects: Vec<Object>,
    light: V,
    light_colour: V,
    light_radius: f64,
    sky_top: V,
    sky_bottom: V,
    camera: Camera,
}

fn num(value: &Value, key: &str, fallback: f64) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(fallback)
}

fn vec3(value: &Value, key: &str, fallback: V) -> V {
    value
        .get(key)
        .and_then(Value::as_array)
        .filter(|items| items.len() == 3)
        .map(|items| {
            V::new(
                items[0].as_f64().unwrap_or(0.0),
                items[1].as_f64().unwrap_or(0.0),
                items[2].as_f64().unwrap_or(0.0),
            )
        })
        .unwrap_or(fallback)
}

fn texture_kind(value: &Value) -> u8 {
    match value.get("texture").and_then(Value::as_str).unwrap_or("none") {
        "checker" => 1,
        "marble" => 2,
        "wood" => 3,
        _ => 0,
    }
}

fn material(value: &Value) -> Mat {
    Mat {
        albedo: vec3(value, "colour", V::new(0.8, 0.8, 0.8)),
        specular: num(value, "specular", 0.2),
        shininess: num(value, "shininess", 32.0),
        reflect: num(value, "reflect", 0.0),
        metallic: num(value, "metallic", 0.0).clamp(0.0, 1.0),
        texture: texture_kind(value),
    }
}

impl PathScene {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let root: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
        let width = num(&root, "width", 320.0) as usize;
        let height = num(&root, "height", 200.0) as usize;
        if width < 8 || height < 8 || width > 4096 || height > 4096 {
            return Err("the frame must be between 8 and 4096 pixels".into());
        }
        let origin = vec3(&root, "camera", V::new(0.0, 1.05, 3.6));
        let target = vec3(&root, "target", V::new(0.15, 0.55, 0.0));
        let forward = target.sub(origin).unit();
        let right = forward.cross(V::new(0.0, 1.0, 0.0)).unit();
        let up = right.cross(forward).unit();
        let mut objects = Vec::new();
        if let Some(items) = root.get("objects").and_then(Value::as_array) {
            for item in items {
                let kind = item.get("type").and_then(Value::as_str).unwrap_or("sphere");
                let shape = match kind {
                    "sphere" => Shape::Sphere {
                        centre: vec3(item, "centre", V::new(0.0, 0.5, 0.0)),
                        radius: num(item, "radius", 0.5).max(0.01),
                    },
                    "box" => Shape::Box {
                        centre: vec3(item, "centre", V::new(0.0, 0.5, 0.0)),
                        half: num(item, "half", 0.5).max(0.01),
                    },
                    "plane" => Shape::Plane { y: num(item, "y", 0.0) },
                    other => return Err(format!("unknown object type {other}")),
                };
                objects.push(Object { shape, mat: material(item) });
            }
        }
        if objects.is_empty() {
            return Err("the scene has no objects".into());
        }
        Ok(Self {
            width,
            height,
            samples: num(&root, "samples", 1.0).clamp(1.0, 16.0) as usize,
            threads: num(&root, "threads", 1.0).clamp(1.0, 64.0) as usize,
            bounces: num(&root, "bounces", 2.0).clamp(0.0, 8.0) as usize,
            aperture: num(&root, "aperture", 0.0).max(0.0),
            exposure: num(&root, "exposure", 0.85).clamp(0.05, 8.0),
            objects,
            light: vec3(&root, "light", V::new(-3.0, 6.0, 4.0)),
            light_colour: vec3(&root, "light_colour", V::new(1.0, 0.96, 0.88)),
            light_radius: num(&root, "light_radius", 0.0).clamp(0.0, 5.0),
            sky_top: vec3(&root, "sky_top", V::new(0.35, 0.55, 0.85)),
            sky_bottom: vec3(&root, "sky_bottom", V::new(0.92, 0.94, 0.97)),
            camera: Camera {
                origin,
                forward,
                right,
                up,
                field: num(&root, "field", 1.0).max(0.2),
                aspect: width as f64 / height as f64,
            },
        })
    }
}

fn hash(a: u64, b: u64, c: u64) -> f64 {
    let mut value = a
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ b.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
        ^ c.wrapping_mul(0x1656_67B1_9E37_79F9);
    value ^= value >> 33;
    value = value.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    value ^= value >> 33;
    (value & 0xFFFFFF) as f64 / 16_777_215.0
}

struct Hit {
    t: f64,
    point: V,
    normal: V,
    mat: Mat,
}

fn hit_object(object: &Object, origin: V, direction: V) -> Option<(f64, V)> {
    match object.shape {
        Shape::Sphere { centre, radius } => {
            let offset = origin.sub(centre);
            let b = offset.dot(direction);
            let c = offset.dot(offset) - radius * radius;
            let discriminant = b * b - c;
            if discriminant < 0.0 {
                return None;
            }
            let root = discriminant.sqrt();
            let near = -b - root;
            let far = -b + root;
            let distance = if near > 1e-4 {
                near
            } else if far > 1e-4 {
                far
            } else {
                return None;
            };
            Some((distance, offset.add(direction.mul(distance)).unit()))
        }
        Shape::Box { centre, half } => {
            let mut near = f64::NEG_INFINITY;
            let mut far = f64::INFINITY;
            let mut axis = 0;
            for index in 0..3 {
                let (origin_axis, direction_axis, centre_axis) = match index {
                    0 => (origin.x, direction.x, centre.x),
                    1 => (origin.y, direction.y, centre.y),
                    _ => (origin.z, direction.z, centre.z),
                };
                if direction_axis.abs() < 1e-9 {
                    if origin_axis < centre_axis - half || origin_axis > centre_axis + half {
                        return None;
                    }
                    continue;
                }
                let mut low = (centre_axis - half - origin_axis) / direction_axis;
                let mut high = (centre_axis + half - origin_axis) / direction_axis;
                if low > high {
                    std::mem::swap(&mut low, &mut high);
                }
                if low > near {
                    near = low;
                    axis = index;
                }
                far = far.min(high);
                if near > far {
                    return None;
                }
            }
            if near <= 1e-4 {
                return None;
            }
            let sign = match axis {
                0 => direction.x.signum(),
                1 => direction.y.signum(),
                _ => direction.z.signum(),
            };
            let normal = match axis {
                0 => V::new(-sign, 0.0, 0.0),
                1 => V::new(0.0, -sign, 0.0),
                _ => V::new(0.0, 0.0, -sign),
            };
            Some((near, normal))
        }
        Shape::Plane { y } => {
            if direction.y.abs() < 1e-9 {
                return None;
            }
            let distance = (y - origin.y) / direction.y;
            if distance > 1e-4 {
                Some((distance, V::new(0.0, 1.0, 0.0)))
            } else {
                None
            }
        }
    }
}

fn trace(scene: &PathScene, origin: V, direction: V) -> Option<Hit> {
    let mut best: Option<Hit> = None;
    for object in &scene.objects {
        if let Some((distance, normal)) = hit_object(object, origin, direction) {
            if best.as_ref().is_none_or(|hit| distance < hit.t) {
                best = Some(Hit {
                    t: distance,
                    point: origin.add(direction.mul(distance)),
                    normal,
                    mat: object.mat,
                });
            }
        }
    }
    best
}

fn sky(scene: &PathScene, direction: V) -> V {
    let t = (direction.y * 0.5 + 0.5).clamp(0.0, 1.0);
    scene.sky_bottom.mul(1.0 - t).add(scene.sky_top.mul(t))
}

fn occluded(scene: &PathScene, origin: V, direction: V) -> bool {
    trace(scene, origin.add(direction.mul(2e-3)), direction).is_some()
}

fn texture_factor(kind: u8, point: V) -> f64 {
    match kind {
        1 => {
            let cell = (point.x * 3.0).floor() + (point.y * 3.0).floor() + (point.z * 3.0).floor();
            if cell as i64 % 2 == 0 { 1.0 } else { 0.55 }
        }
        2 => {
            let bands = (point.x * 3.0 + 2.0 * (point.y * 2.0 + point.z).sin()).sin();
            0.75 + 0.25 * bands
        }
        3 => {
            let radius = (point.x * point.x + point.z * point.z).sqrt() * 9.0;
            let rings = (radius + 1.5 * point.y).sin();
            0.72 + 0.28 * rings
        }
        _ => 1.0,
    }
}

fn albedo_at(mat: Mat, point: V) -> V {
    mat.albedo.mul(texture_factor(mat.texture, point))
}

fn direct(scene: &PathScene, hit: &Hit, view: V) -> V {
    let seed = ((hit.point.x * 7919.0 + hit.point.y * 104_729.0 + hit.point.z * 1_299_709.0).abs()
        * 1000.0) as u64;
    let angle = 2.0 * std::f64::consts::PI * hash(seed, 3, 1);
    let radius = scene.light_radius * hash(seed, 5, 2).sqrt();
    let sample = scene.light.add(V::new(radius * angle.cos(), 0.0, radius * angle.sin()));
    let to_light = sample.sub(hit.point);
    let distance = to_light.len();
    let direction = to_light.mul(1.0 / distance.max(1e-9));
    if occluded(scene, hit.point, direction) {
        return V::new(0.0, 0.0, 0.0);
    }
    let normal = if hit.normal.dot(view) < 0.0 {
        hit.normal.mul(-1.0)
    } else {
        hit.normal
    };
    let albedo = albedo_at(hit.mat, hit.point);
    let diffuse = normal.dot(direction).max(0.0);
    let halfway = direction.add(view.mul(-1.0)).unit();
    let cosine = normal.dot(halfway).max(0.0);
    let fresnel = 0.04 + 0.96 * (1.0 - cosine).powi(5);
    let specular = cosine.powf(hit.mat.shininess) * (hit.mat.specular + hit.mat.metallic * fresnel);
    let falloff = 120.0 / (distance * distance + 1.0);
    let ambient = 0.01 + 0.03 * normal.y.max(0.0);
    albedo
        .mul(ambient)
        .add(albedo.hadamard(scene.light_colour).mul(diffuse * falloff * (1.0 - hit.mat.metallic * 0.6)))
        .add(scene.light_colour.mul(specular * falloff))
}

fn cosine_direction(normal: V, a: f64, b: f64) -> V {
    let tangent = if normal.y.abs() < 0.9 {
        normal.cross(V::new(0.0, 1.0, 0.0)).unit()
    } else {
        normal.cross(V::new(1.0, 0.0, 0.0)).unit()
    };
    let bitangent = normal.cross(tangent);
    let radius = a.sqrt();
    let phi = 2.0 * std::f64::consts::PI * b;
    normal
        .mul((1.0 - a).max(0.0).sqrt())
        .add(tangent.mul(radius * phi.cos()))
        .add(bitangent.mul(radius * phi.sin()))
        .unit()
}

fn radiance(scene: &PathScene, origin: V, direction: V, depth: usize, seed: u64) -> V {
    let Some(hit) = trace(scene, origin, direction) else {
        return sky(scene, direction).mul(0.40);
    };
    let mut colour = direct(scene, &hit, direction);
    if depth >= scene.bounces {
        return colour;
    }
    let a = hash(seed, depth as u64, 17);
    let b = hash(seed, depth as u64, 29);
    let bounce = cosine_direction(hit.normal, a, b);
    let next = radiance(
        scene,
        hit.point.add(hit.normal.mul(2e-3)),
        bounce,
        depth + 1,
        seed.wrapping_add(1),
    );
    let weight = if depth == 0 { 0.45 } else { 0.65 };
    colour = colour.add(albedo_at(hit.mat, hit.point).hadamard(clamp_v(next, 3.5)).mul(weight));
    if hit.mat.reflect > 0.0 && depth < 2 {
        let mirror = direction.sub(hit.normal.mul(2.0 * direction.dot(hit.normal)));
        let reflected = radiance(
            scene,
            hit.point.add(hit.normal.mul(2e-3)),
            mirror,
            depth + 1,
            seed.wrapping_add(7),
        );
        colour = colour.mul(1.0 - hit.mat.reflect).add(reflected.mul(hit.mat.reflect));
    }
    colour
}

fn clamp_v(value: V, ceiling: f64) -> V {
    V::new(value.x.min(ceiling), value.y.min(ceiling), value.z.min(ceiling))
}

fn tone(value: f64) -> u8 {
    let mapped = value / (1.0 + value);
    (mapped.powf(1.0 / 2.2).clamp(0.0, 1.0) * 255.0).round() as u8
}

fn render_rows(scene: &PathScene, start: usize, end: usize) -> Vec<u8> {
    let step = 1.0 / scene.samples as f64;
    let mut pixels = Vec::with_capacity((end - start) * scene.width * 3);
    for y in start..end {
        for x in 0..scene.width {
            let mut total = V::new(0.0, 0.0, 0.0);
            for sy in 0..scene.samples {
                for sx in 0..scene.samples {
                    let px = (x as f64 + (sx as f64 + 0.5) * step) / scene.width as f64;
                    let py = (y as f64 + (sy as f64 + 0.5) * step) / scene.height as f64;
                    let jitter_x = hash(x as u64, y as u64, 11) - 0.5;
                    let jitter_y = hash(x as u64, y as u64, 23) - 0.5;
                    let origin = scene
                        .camera
                        .origin
                        .add(scene.camera.right.mul(jitter_x * scene.aperture))
                        .add(scene.camera.up.mul(jitter_y * scene.aperture));
                    let direction = scene
                        .camera
                        .forward
                        .add(
                            scene
                                .camera
                                .right
                                .mul((px - 0.5) * scene.camera.aspect * scene.camera.field),
                        )
                        .add(scene.camera.up.mul((0.5 - py) * scene.camera.field))
                        .unit();
                    let seed = (x as u64) << 32 | (y as u64) << 8 | (sx * scene.samples + sy) as u64;
                    total = total.add(radiance(scene, origin, direction, 0, seed));
                }
            }
            let count = (scene.samples * scene.samples) as f64;
            pixels.push(tone(total.x * scene.exposure / count));
            pixels.push(tone(total.y * scene.exposure / count));
            pixels.push(tone(total.z * scene.exposure / count));
        }
    }
    pixels
}

pub fn render(scene: &PathScene) -> Vec<u8> {
    if scene.threads <= 1 {
        return render_rows(scene, 0, scene.height);
    }
    let per_thread = scene.height.div_ceil(scene.threads);
    let mut chunks = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..scene.threads {
            let start = index * per_thread;
            let end = ((index + 1) * per_thread).min(scene.height);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || render_rows(scene, start, end)));
        }
        for handle in handles {
            chunks.push(handle.join().expect("a path tracing thread panicked"));
        }
    });
    chunks.concat()
}

pub fn render_json_to_ppm(text: &str) -> Result<(Vec<u8>, f64, usize, usize, usize), String> {
    let scene = PathScene::from_json(text)?;
    let started = Instant::now();
    let pixels = render(&scene);
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    let header = format!("P6\n{} {}\n255\n", scene.width, scene.height);
    let mut output = Vec::with_capacity(header.len() + pixels.len());
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(&pixels);
    Ok((output, elapsed, scene.width * scene.height, scene.threads, scene.bounces))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple() -> String {
        r#"{"width":32,"height":20,"samples":1,"threads":1,"bounces":2,
            "camera":[0,1.05,3.6],"target":[0,0.5,0],
            "objects":[
              {"type":"sphere","centre":[-0.6,0.55,0],"radius":0.55,"colour":[0.2,0.5,0.9]},
              {"type":"box","centre":[1.2,0.5,0],"half":0.5,"colour":[0.8,0.3,0.2]},
              {"type":"plane","y":0,"colour":[0.8,0.8,0.8]}
            ]}"#
            .to_string()
    }

    #[test]
    fn scene_parses_and_renders() {
        let scene = PathScene::from_json(&simple()).unwrap();
        assert_eq!(scene.width, 32);
        assert_eq!(scene.objects.len(), 3);
        let pixels = render(&scene);
        assert_eq!(pixels.len(), 32 * 20 * 3);
        assert!(pixels.iter().any(|value| *value > 30));
    }

    #[test]
    fn bad_scenes_are_refused() {
        assert!(PathScene::from_json("{}").is_err());
        assert!(PathScene::from_json(r#"{"objects":[{"type":"torus"}]}"#).is_err());
        assert!(PathScene::from_json(r#"{"width":2,"height":2,"objects":[{"type":"plane"}]}"#).is_err());
    }

    #[test]
    fn threads_match_single_thread() {
        let mut scene = PathScene::from_json(&simple()).unwrap();
        scene.threads = 1;
        let single = render(&scene);
        scene.threads = 4;
        let multi = render(&scene);
        assert_eq!(single, multi);
    }
}
