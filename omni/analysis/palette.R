# Build the five-stop palette the renderer uses, as tidy CSV.
# LCH -> Lab -> XYZ (D65) -> linear sRGB -> gamma. Base R only, no packages.

lch_to_rgb <- function(h, chroma, luminance) {
  radians <- h * pi / 180
  a <- chroma * cos(radians)
  b <- chroma * sin(radians)
  fy <- (luminance + 16) / 116
  fx <- fy + a / 500
  fz <- fy - b / 200
  inverse <- function(t) if (t^3 > 0.008856) t^3 else (t - 16 / 116) / 7.787
  x <- 95.047 * inverse(fx)
  y <- 100.000 * inverse(fy)
  z <- 108.883 * inverse(fz)
  linear <- c(
    3.2406 * x - 1.5372 * y - 0.4986 * z,
    -0.9689 * x + 1.8758 * y + 0.0415 * z,
    0.0557 * x - 0.2040 * y + 1.0570 * z
  ) / 100
  gamma <- function(value) {
    value <- min(max(value, 0), 1)
    if (value > 0.0031308) 1.055 * value^(1 / 2.4) - 0.055 else 12.92 * value
  }
  round(vapply(linear, gamma, numeric(1)) * 255)
}

stops <- data.frame(
  name = c("night", "sea", "ember", "gold", "light"),
  hue = c(232, 226, 22, 43, 210),
  chroma = c(38, 46, 78, 62, 8),
  luminance = c(12, 28, 62, 78, 96),
  stringsAsFactors = FALSE
)

palette <- do.call(rbind, lapply(seq_len(nrow(stops)), function(i) {
  rgb <- lch_to_rgb(stops$hue[i], stops$chroma[i], stops$luminance[i])
  data.frame(
    name = stops$name[i],
    r = rgb[1], g = rgb[2], b = rgb[3],
    stringsAsFactors = FALSE
  )
}))

utils::write.csv(palette, file.path("analysis", "data", "palette.csv"), row.names = FALSE)
cat("wrote analysis/data/palette.csv with", nrow(palette), "stops\n")
