//! CPU ray tracer: spheres, a ground plane and a triangle mesh, with shadows.
//!
//! No GPU and no crates. The scene is fixed so the output is deterministic; the
//! caller chooses width, height and samples per axis. Rays per second are
//! reported so quality and speed are both visible.

use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }
    fn add(self, other: Vec3) -> Vec3 {
        Vec3::new(self.x + other.x, self.y + other.y, self.z + other.z)
    }
    fn sub(self, other: Vec3) -> Vec3 {
        Vec3::new(self.x - other.x, self.y - other.y, self.z - other.z)
    }
    fn mul(self, k: f64) -> Vec3 {
        Vec3::new(self.x * k, self.y * k, self.z * k)
    }
    fn dot(self, other: Vec3) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }
    fn length(self) -> f64 {
        self.dot(self).sqrt()
    }
    fn normalised(self) -> Vec3 {
        let length = self.length().max(1e-12);
        self.mul(1.0 / length)
    }
}

#[derive(Clone, Copy)]
struct Ray {
    origin: Vec3,
    direction: Vec3,
}

#[derive(Clone, Copy)]
struct Material {
    colour: Vec3,
    specular: f64,
    shininess: f64,
    reflect: f64,
    texture: u8,
}

#[derive(Clone, Copy)]
struct Sphere {
    centre: Vec3,
    radius: f64,
    material: Material,
}

struct Triangle {
    a: Vec3,
    b: Vec3,
    c: Vec3,
    normal: Vec3,
    material: Material,
}

pub struct Scene3d {
    pub width: usize,
    pub height: usize,
    pub samples: usize,
    pub angle: f64,
    pub aperture: f64,
    pub threads: usize,
    spheres: Vec<Sphere>,
    triangles: Vec<Triangle>,
    light: Vec3,
    sky_top: Vec3,
    sky_bottom: Vec3,
}

impl Default for Scene3d {
    fn default() -> Self {
        let mut triangles = Vec::new();
        // A cube at the right, built from 12 triangles.
        let centre = Vec3::new(1.6, 0.55, -0.4);
        let half = 0.55;
        let corners = [
            Vec3::new(centre.x - half, 0.0, centre.z - half),
            Vec3::new(centre.x + half, 0.0, centre.z - half),
            Vec3::new(centre.x + half, 0.0, centre.z + half),
            Vec3::new(centre.x - half, 0.0, centre.z + half),
            Vec3::new(centre.x - half, centre.y + half, centre.z - half),
            Vec3::new(centre.x + half, centre.y + half, centre.z - half),
            Vec3::new(centre.x + half, centre.y + half, centre.z + half),
            Vec3::new(centre.x - half, centre.y + half, centre.z + half),
        ];
        let faces = [
            [0, 1, 2], [0, 2, 3], [4, 6, 5], [4, 7, 6],
            [0, 4, 5], [0, 5, 1], [1, 5, 6], [1, 6, 2],
            [2, 6, 7], [2, 7, 3], [3, 7, 4], [3, 4, 0],
        ];
        let material = Material {
            colour: Vec3::new(0.85, 0.35, 0.28),
            specular: 0.3,
            shininess: 24.0,
            reflect: 0.0,
            texture: 1,
        };
        for face in faces {
            let a = corners[face[0]];
            let b = corners[face[1]];
            let c = corners[face[2]];
            triangles.push(Triangle {
                a,
                b,
                c,
                normal: b.sub(a).cross(c.sub(a)).normalised(),
                material,
            });
        }
        Self {
            width: 480,
            height: 300,
            samples: 2,
            angle: 0.0,
            aperture: 0.0,
            threads: 1,
            spheres: vec![
                Sphere {
                    centre: Vec3::new(-0.6, 0.55, 0.0),
                    radius: 0.55,
                    material: Material {
                        colour: Vec3::new(0.25, 0.55, 0.95),
                        specular: 0.8,
                        shininess: 96.0,
                        reflect: 0.15,
                        texture: 0,
                    },
                },
                Sphere {
                    centre: Vec3::new(0.35, 0.3, 0.9),
                    radius: 0.3,
                    material: Material {
                        colour: Vec3::new(0.95, 0.78, 0.25),
                        specular: 0.6,
                        shininess: 64.0,
                        reflect: 0.0,
                        texture: 2,
                    },
                },
            ],
            triangles,
            light: Vec3::new(-3.0, 6.0, 4.0),
            sky_top: Vec3::new(0.35, 0.55, 0.85),
            sky_bottom: Vec3::new(0.92, 0.94, 0.97),
        }
    }
}

impl Vec3 {
    fn cross(self, other: Vec3) -> Vec3 {
        Vec3::new(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x,
        )
    }
}

fn hash3(x: i64, y: i64, z: i64) -> f64 {
    let mut value = (x as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (y as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
        ^ (z as u64).wrapping_mul(0x1656_67B1_9E37_79F9);
    value ^= value >> 33;
    value = value.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    value ^= value >> 33;
    (value & 0xFFFFFF) as f64 / 16_777_215.0
}

fn value_noise(point: Vec3) -> f64 {
    let x = point.x.floor() as i64;
    let y = point.y.floor() as i64;
    let z = point.z.floor() as i64;
    let fx = point.x - point.x.floor();
    let fy = point.y - point.y.floor();
    let fz = point.z - point.z.floor();
    let sx = fx * fx * (3.0 - 2.0 * fx);
    let sy = fy * fy * (3.0 - 2.0 * fy);
    let sz = fz * fz * (3.0 - 2.0 * fz);
    let mut total = 0.0;
    for dz in 0..2 {
        for dy in 0..2 {
            for dx in 0..2 {
                let weight = (if dx == 0 { 1.0 - sx } else { sx })
                    * (if dy == 0 { 1.0 - sy } else { sy })
                    * (if dz == 0 { 1.0 - sz } else { sz });
                total += weight * hash3(x + dx as i64, y + dy as i64, z + dz as i64);
            }
        }
    }
    total
}

fn fbm(point: Vec3) -> f64 {
    let mut sum = 0.0;
    let mut amplitude = 0.5;
    let mut frequency = 1.0;
    for _ in 0..4 {
        sum += amplitude * value_noise(point.mul(frequency));
        amplitude *= 0.5;
        frequency *= 2.0;
    }
    sum
}

fn textured(material: &Material, point: Vec3) -> Vec3 {
    match material.texture {
        1 => {
            let vein = (point.x * 3.0 + fbm(point.mul(2.5)) * 6.0).sin().abs();
            material
                .colour
                .mul(0.55 + 0.45 * vein)
                .add(Vec3::new(0.08, 0.05, 0.04))
        }
        2 => material.colour.mul(0.75 + 0.5 * fbm(point.mul(9.0))),
        _ => material.colour,
    }
}

fn intersect_sphere(ray: &Ray, sphere: &Sphere) -> Option<f64> {
    let offset = ray.origin.sub(sphere.centre);
    let b = offset.dot(ray.direction);
    let c = offset.dot(offset) - sphere.radius * sphere.radius;
    let discriminant = b * b - c;
    if discriminant < 0.0 {
        return None;
    }
    let root = discriminant.sqrt();
    let near = -b - root;
    let far = -b + root;
    if near > 1e-4 {
        Some(near)
    } else if far > 1e-4 {
        Some(far)
    } else {
        None
    }
}

fn intersect_triangle(ray: &Ray, triangle: &Triangle) -> Option<f64> {
    let edge1 = triangle.b.sub(triangle.a);
    let edge2 = triangle.c.sub(triangle.a);
    let pvec = ray.direction.cross(edge2);
    let determinant = edge1.dot(pvec);
    if determinant.abs() < 1e-9 {
        return None;
    }
    let inverse = 1.0 / determinant;
    let tvec = ray.origin.sub(triangle.a);
    let u = tvec.dot(pvec) * inverse;
    if !(0.0..=1.0).contains(&u) {
        return None;
    }
    let qvec = tvec.cross(edge1);
    let v = ray.direction.dot(qvec) * inverse;
    if v < 0.0 || u + v > 1.0 {
        return None;
    }
    let distance = edge2.dot(qvec) * inverse;
    if distance > 1e-4 {
        Some(distance)
    } else {
        None
    }
}

struct Hit {
    distance: f64,
    point: Vec3,
    normal: Vec3,
    material: Material,
}

fn trace(scene: &Scene3d, ray: &Ray) -> Option<Hit> {
    let mut best: Option<Hit> = None;
    for sphere in &scene.spheres {
        if let Some(distance) = intersect_sphere(ray, sphere) {
            if best.as_ref().is_none_or(|hit| distance < hit.distance) {
                let point = ray.origin.add(ray.direction.mul(distance));
                best = Some(Hit {
                    distance,
                    point,
                    normal: point.sub(sphere.centre).normalised(),
                    material: sphere.material,
                });
            }
        }
    }
    for triangle in &scene.triangles {
        if let Some(distance) = intersect_triangle(ray, triangle) {
            if best.as_ref().is_none_or(|hit| distance < hit.distance) {
                let point = ray.origin.add(ray.direction.mul(distance));
                let mut normal = triangle.normal;
                if normal.dot(ray.direction) > 0.0 {
                    normal = normal.mul(-1.0);
                }
                best = Some(Hit {
                    distance,
                    point,
                    normal,
                    material: triangle.material,
                });
            }
        }
    }
    // Ground plane at y = 0.
    if ray.direction.y.abs() > 1e-9 {
        let distance = -ray.origin.y / ray.direction.y;
        if distance > 1e-4 && best.as_ref().is_none_or(|hit| distance < hit.distance) {
            let point = ray.origin.add(ray.direction.mul(distance));
            let checker = ((point.x.floor() + point.z.floor()) as i64).rem_euclid(2) == 0;
            let base = if checker { 0.82 } else { 0.72 };
            best = Some(Hit {
                distance,
                point,
                normal: Vec3::new(0.0, 1.0, 0.0),
                material: Material {
                    colour: Vec3::new(base, base, base * 1.02),
                    specular: 0.15,
                    shininess: 16.0,
                    reflect: 0.0,
                    texture: 0,
                },
            });
        }
    }
    best
}

fn shadowed(scene: &Scene3d, point: Vec3, direction: Vec3) -> bool {
    let ray = Ray {
        origin: point.add(direction.mul(1e-3)),
        direction,
    };
    trace(scene, &ray).is_some()
}

fn shade(scene: &Scene3d, ray: &Ray, hit: &Hit, depth: usize) -> Vec3 {
    let light_direction = scene.light.sub(hit.point).normalised();
    let mut shadow = 0.0;
    let jitter = [
        (0.0, 0.0),
        (0.35, 0.1),
        (-0.3, 0.2),
        (0.1, -0.35),
    ];
    for (dx, dy) in jitter {
        let target = scene.light.add(Vec3::new(dx, dy, 0.0));
        let direction = target.sub(hit.point).normalised();
        if !shadowed(scene, hit.point, direction) {
            shadow += 0.25;
        }
    }
    let diffuse = hit.normal.dot(light_direction).max(0.0);
    let view = ray.direction.mul(-1.0);
    let halfway = light_direction.add(view).normalised();
    let specular = hit
        .normal
        .dot(halfway)
        .max(0.0)
        .powf(hit.material.shininess);
    // Four cosine-weighted hemisphere rays, short range: cheap ambient occlusion.
    let mut occlusion = 0.0;
    let tangent = if hit.normal.y.abs() < 0.9 {
        hit.normal.cross(Vec3::new(0.0, 1.0, 0.0)).normalised()
    } else {
        hit.normal.cross(Vec3::new(1.0, 0.0, 0.0)).normalised()
    };
    let bitangent = hit.normal.cross(tangent);
    for index in 0..4 {
        let angle = index as f64 * 1.570_796_3 + 0.4;
        let direction = hit
            .normal
            .add(tangent.mul(angle.cos() * 0.7))
            .add(bitangent.mul(angle.sin() * 0.7))
            .normalised();
        if shadowed(scene, hit.point, direction) {
            occlusion += 0.25;
        }
    }
    let ambient = (0.18 + 0.22 * hit.normal.y.max(0.0)) * (1.0 - 0.45 * occlusion);
    let surface = textured(&hit.material, hit.point);
    let mut colour = surface
        .mul(ambient + diffuse * shadow * 0.95)
        .add(Vec3::new(1.0, 0.96, 0.88).mul(specular * hit.material.specular * shadow));

    if hit.material.reflect > 0.0 && depth < 3 {
        let direction = ray.direction.sub(hit.normal.mul(2.0 * ray.direction.dot(hit.normal)));
        let reflected = Ray {
            origin: hit.point.add(hit.normal.mul(1e-3)),
            direction: direction.normalised(),
        };
        if let Some(next) = trace(scene, &reflected) {
            let bounce = shade(scene, &reflected, &next, depth + 1);
            colour = colour.mul(1.0 - hit.material.reflect).add(bounce.mul(hit.material.reflect));
        }
    }
    colour
}

fn sky(scene: &Scene3d, direction: Vec3) -> Vec3 {
    let t = (direction.y * 0.5 + 0.5).clamp(0.0, 1.0);
    scene.sky_bottom.mul(1.0 - t).add(scene.sky_top.mul(t))
}

fn tone_map(value: f64) -> u8 {
    let mapped = value / (1.0 + value);
    let gamma = mapped.powf(1.0 / 2.2);
    (gamma.clamp(0.0, 1.0) * 255.0).round() as u8
}

fn bayer(x: usize, y: usize) -> f64 {
    const MATRIX: [[f64; 4]; 4] = [
        [0.0, 8.0, 2.0, 10.0],
        [12.0, 4.0, 14.0, 6.0],
        [3.0, 11.0, 1.0, 9.0],
        [15.0, 7.0, 13.0, 5.0],
    ];
    MATRIX[y % 4][x % 4] / 16.0 - 0.5
}

fn render_rows(scene: &Scene3d, start: usize, end: usize) -> Vec<u8> {
    let aspect = scene.width as f64 / scene.height as f64;
    let base = Vec3::new(0.0, 1.05, 3.6);
    let cos_a = scene.angle.cos();
    let sin_a = scene.angle.sin();
    let origin = Vec3::new(
        base.x * cos_a + base.z * sin_a,
        base.y,
        -base.x * sin_a + base.z * cos_a,
    );
    let target = Vec3::new(0.15, 0.55, 0.0);
    let forward = target.sub(origin).normalised();
    let right = forward.cross(Vec3::new(0.0, 1.0, 0.0)).normalised();
    let up = right.cross(forward).normalised();
    let field = 1.0_f64;
    let mut pixels = Vec::with_capacity((end - start) * scene.width * 3);
    let step = 1.0 / scene.samples as f64;
    for y in start..end {
        for x in 0..scene.width {
            let mut colour = Vec3::new(0.0, 0.0, 0.0);
            for sy in 0..scene.samples {
                for sx in 0..scene.samples {
                    let px = (x as f64 + (sx as f64 + 0.5) * step) / scene.width as f64;
                    let py = (y as f64 + (sy as f64 + 0.5) * step) / scene.height as f64;
                    let direction = forward
                        .add(right.mul((px - 0.5) * aspect * field))
                        .add(up.mul((0.5 - py) * field))
                        .normalised();
                    // Depth of field: jitter the origin on a small disk.
                    let jitter_x = hash3(x as i64, y as i64, 11) - 0.5;
                    let jitter_y = hash3(x as i64, y as i64, 23) - 0.5;
                    let ray_origin = origin
                        .add(right.mul(jitter_x * scene.aperture))
                        .add(up.mul(jitter_y * scene.aperture));
                    let ray = Ray { origin: ray_origin, direction };
                    let value = match trace(scene, &ray) {
                        Some(hit) => shade(scene, &ray, &hit, 0),
                        None => sky(scene, direction),
                    };
                    colour = colour.add(value);
                }
            }
            let count = (scene.samples * scene.samples) as f64;
            let dither = bayer(x, y) / 255.0;
            pixels.push(tone_map((colour.x / count) * (1.0 + dither)));
            pixels.push(tone_map((colour.y / count) * (1.0 + dither)));
            pixels.push(tone_map((colour.z / count) * (1.0 + dither)));
        }
    }
    pixels
}

pub fn render(scene: &Scene3d) -> Vec<u8> {
    let threads = scene.threads.clamp(1, 64);
    if threads == 1 {
        return render_rows(scene, 0, scene.height);
    }
    let rows_per_thread = scene.height.div_ceil(threads);
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..threads {
            let start = index * rows_per_thread;
            let end = ((index + 1) * rows_per_thread).min(scene.height);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || render_rows(scene, start, end)));
        }
        for handle in handles {
            chunks.push(handle.join().expect("a render thread panicked"));
        }
    });
    chunks.concat()
}

pub fn to_ppm(scene: &Scene3d, pixels: &[u8]) -> Vec<u8> {
    let header = format!("P6\n{} {}\n255\n", scene.width, scene.height);
    let mut output = Vec::with_capacity(header.len() + pixels.len());
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(pixels);
    output
}

pub fn render3d_to_ppm(
    width: usize,
    height: usize,
    samples: usize,
    threads: usize,
    angle: f64,
    aperture: f64,
) -> (Vec<u8>, f64, usize) {
    let scene = Scene3d {
        width,
        height,
        samples,
        threads,
        angle,
        aperture,
        ..Scene3d::default()
    };
    let started = Instant::now();
    let pixels = render(&scene);
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let output = to_ppm(&scene, &pixels);
    (output, elapsed_ms, width * height * samples * samples)
}
