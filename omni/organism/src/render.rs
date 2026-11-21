//! CPU raster core: supersampled scene rendering with no GPU and no crates.
//!
//! The scene is a deterministic function of the pixel position: sky gradient,
//! sun with a soft halo, layered hills, water with a shimmer, vignette and
//! ordered dither. Samples per axis are configurable; cost grows with the
//! square, which is why the caller can trade quality for time.

use std::time::Instant;

#[derive(Clone, Copy)]
pub struct Rgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

impl Rgb {
    pub const fn new(r: f64, g: f64, b: f64) -> Self {
        Self { r, g, b }
    }
    fn mix(self, other: Rgb, t: f64) -> Rgb {
        let t = t.clamp(0.0, 1.0);
        Rgb::new(
            self.r + (other.r - self.r) * t,
            self.g + (other.g - self.g) * t,
            self.b + (other.b - self.b) * t,
        )
    }
    fn scaled(self, k: f64) -> Rgb {
        Rgb::new(self.r * k, self.g * k, self.b * k)
    }
    fn to_byte(self) -> [u8; 3] {
        [
            (self.r.clamp(0.0, 1.0) * 255.0).round() as u8,
            (self.g.clamp(0.0, 1.0) * 255.0).round() as u8,
            (self.b.clamp(0.0, 1.0) * 255.0).round() as u8,
        ]
    }
}

pub struct Scene {
    pub width: usize,
    pub height: usize,
    pub samples: usize,
    pub palette: [Rgb; 5],
}

impl Default for Scene {
    fn default() -> Self {
        Self {
            width: 480,
            height: 300,
            samples: 2,
            palette: [
                Rgb::new(0.04, 0.06, 0.13),
                Rgb::new(0.16, 0.22, 0.45),
                Rgb::new(0.85, 0.45, 0.22),
                Rgb::new(0.98, 0.78, 0.35),
                Rgb::new(0.93, 0.95, 1.0),
            ],
        }
    }
}

fn smoothstep(edge0: f64, edge1: f64, x: f64) -> f64 {
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
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

fn sample(scene: &Scene, px: f64, py: f64) -> Rgb {
    let w = scene.width as f64;
    let h = scene.height as f64;
    let u = px / w;
    let v = py / h;
    let horizon = 0.58;

    let mut color = if v < horizon {
        let t = (v / horizon).powf(1.3);
        scene.palette[0].mix(scene.palette[2], t)
    } else {
        let t = ((v - horizon) / (1.0 - horizon)).powf(0.8);
        scene.palette[1].scaled(0.75).mix(scene.palette[0], t)
    };

    // Sun with a halo, lower left of the horizon.
    let sun_x = 0.30;
    let sun_y = 0.50;
    let dx = (u - sun_x) * (w / h);
    let dy = v - sun_y;
    let distance = (dx * dx + dy * dy).sqrt();
    let halo = (1.0 - smoothstep(0.02, 0.30, distance)) * 0.55;
    color = color.mix(scene.palette[3], halo);
    let disc = 1.0 - smoothstep(0.035, 0.05, distance);
    color = color.mix(scene.palette[4], disc);

    // Two hill layers: a smooth ridge plus a nearer, darker one.
    let ridge = 0.62 + 0.05 * (u * 7.0).sin() + 0.02 * (u * 17.0).cos();
    if v > ridge {
        let depth = smoothstep(ridge, ridge + 0.18, v);
        color = color.mix(scene.palette[0].scaled(0.55), 0.85 - 0.35 * depth);
    }
    let near = 0.74 + 0.03 * (u * 5.0 + 1.3).sin();
    if v > near {
        color = color.mix(scene.palette[0].scaled(0.35), 0.9);
    }

    // Water shimmer below the near ridge.
    if v > near {
        let wave = ((u * 60.0 + v * 120.0).sin() * 0.5 + 0.5).powi(6);
        color = color.mix(scene.palette[3], wave * 0.25);
    }

    // Vignette.
    let cx = u - 0.5;
    let cy = v - 0.5;
    let vignette = 1.0 - 0.55 * (cx * cx + cy * cy);
    color.scaled(vignette.max(0.0))
}

pub fn render(scene: &Scene) -> Vec<u8> {
    let mut pixels = Vec::with_capacity(scene.width * scene.height * 3);
    let step = 1.0 / scene.samples as f64;
    for y in 0..scene.height {
        for x in 0..scene.width {
            let mut red = 0.0;
            let mut green = 0.0;
            let mut blue = 0.0;
            for sy in 0..scene.samples {
                for sx in 0..scene.samples {
                    let px = x as f64 + (sx as f64 + 0.5) * step;
                    let py = y as f64 + (sy as f64 + 0.5) * step;
                    let color = sample(scene, px, py);
                    red += color.r;
                    green += color.g;
                    blue += color.b;
                }
            }
            let count = (scene.samples * scene.samples) as f64;
            let dither = bayer(x, y) / 255.0;
            let pixel = Rgb::new(red / count, green / count, blue / count).scaled(1.0 + dither);
            pixels.extend_from_slice(&pixel.to_byte());
        }
    }
    pixels
}

pub fn to_ppm(scene: &Scene, pixels: &[u8]) -> Vec<u8> {
    let header = format!("P6\n{} {}\n255\n", scene.width, scene.height);
    let mut output = Vec::with_capacity(header.len() + pixels.len());
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(pixels);
    output
}

pub fn render_to_ppm(width: usize, height: usize, samples: usize) -> (Vec<u8>, f64, usize) {
    let scene = Scene {
        width,
        height,
        samples,
        ..Scene::default()
    };
    let started = Instant::now();
    let pixels = render(&scene);
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let output = to_ppm(&scene, &pixels);
    (output, elapsed_ms, width * height)
}
