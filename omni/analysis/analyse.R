#!/usr/bin/env Rscript
# Analyse the CSV export produced by `omnishield export`.
# Usage: Rscript analysis/analyse.R [data_dir] [out_dir]
#
# Writes tidy tables and base-R charts. No packages required.

flags <- grep("^--file=", commandArgs(trailingOnly = FALSE), value = TRUE)
script_path <- if (length(flags)) {
  dirname(normalizePath(sub("^--file=", "", flags[[1]])))
} else {
  "analysis"
}
source(file.path(script_path, "lib.R"))

args <- commandArgs(trailingOnly = TRUE)
data_dir <- if (length(args) >= 1) args[[1]] else "analysis/data"
out_dir <- if (length(args) >= 2) args[[2]] else "analysis/out"
dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)

features <- read_csv_safe(file.path(data_dir, "features.csv"))
components <- read_csv_safe(file.path(data_dir, "components.csv"))
doctor <- read_csv_safe(file.path(data_dir, "doctor.csv"))
memory <- read_csv_safe(file.path(data_dir, "memory.csv"))
payments <- read_csv_safe(file.path(data_dir, "payments.csv"))
audit <- read_csv_safe(file.path(data_dir, "audit.csv"))
stealth <- read_csv_safe(file.path(data_dir, "stealth.csv"))
prediction <- read_csv_safe(file.path(data_dir, "prediction.csv"))
layers <- read_csv_safe(file.path(data_dir, "layers.csv"))
image_quality <- read_csv_safe(file.path(data_dir, "image_quality.csv"))

metrics <- data.frame(metric = character(), value = character(), stringsAsFactors = FALSE)
add_metric <- function(name, value) {
  metrics <<- rbind(
    metrics,
    data.frame(metric = name, value = as.character(value), stringsAsFactors = FALSE)
  )
}

status_levels <- c(
  "implemented", "partial", "external", "not_implemented",
  "undefined", "refused", "duplicate"
)

if (!is.null(features)) {
  counts <- table(factor(features$status, levels = status_levels))
  status_counts <- data.frame(status = names(counts), features = as.integer(counts))
  utils::write.csv(status_counts, file.path(out_dir, "status_counts.csv"), row.names = FALSE)

  features$built <- features$status %in% c("implemented", "partial")
  built <- sum(features$built)
  add_metric("features_total", nrow(features))
  add_metric("features_built", built)
  add_metric("coverage_pct", pct(built, nrow(features)))

  groups <- sort(unique(features$group))
  by_group <- data.frame(
    group = groups,
    features = as.integer(table(features$group)[groups]),
    built = as.integer(tapply(features$built, features$group, sum)[groups]),
    stringsAsFactors = FALSE
  )
  by_group$coverage_pct <- pct(by_group$built, by_group$features)
  by_group <- by_group[order(-by_group$coverage_pct, by_group$group), ]
  utils::write.csv(by_group, file.path(out_dir, "by_group.csv"), row.names = FALSE)

  png_open(file.path(out_dir, "status.png"), height = 620)
  cols <- c("#2f855a", "#38a169", "#d69e2e", "#e53e3e", "#a0aec0", "#4a5568", "#c05621")
  graphics::barplot(
    status_counts$features,
    names.arg = status_counts$status,
    col = cols,
    las = 2,
    cex.names = 0.8,
    main = "Features by status",
    ylab = "features"
  )
  png_close()

  png_open(file.path(out_dir, "coverage_by_group.png"), height = 900)
  graphics::par(mar = c(4, 15, 3, 1))
  graphics::barplot(
    rev(by_group$coverage_pct),
    names.arg = rev(by_group$group),
    horiz = TRUE,
    las = 1,
    cex.names = 0.75,
    xlim = c(0, 100),
    col = "#2b6cb0",
    main = "Coverage by group (%)",
    xlab = "% of features with running code"
  )
  graphics::abline(v = mean(by_group$coverage_pct), lty = 2, col = "#c53030")
  png_close()
}

if (!is.null(components)) {
  ok <- sum(tolower(components$ok) == "true", na.rm = TRUE)
  add_metric("components_total", nrow(components))
  add_metric("components_ok", ok)
}

if (!is.null(doctor)) {
  passed <- sum(tolower(doctor$ok) == "true", na.rm = TRUE)
  add_metric("doctor_checks", nrow(doctor))
  add_metric("doctor_passed", passed)
  add_metric("doctor_total_ms", sum(doctor$ms, na.rm = TRUE))
  add_metric("doctor_slowest", doctor$check[which.max(doctor$ms)])

  png_open(file.path(out_dir, "doctor_ms.png"), height = 620)
  graphics::barplot(
    doctor$ms,
    names.arg = doctor$check,
    las = 2,
    cex.names = 0.8,
    col = ifelse(tolower(doctor$ok) == "true", "#2f855a", "#c53030"),
    main = "Doctor check duration (ms)",
    ylab = "ms"
  )
  png_close()
}

if (!is.null(memory)) {
  add_metric("memory_items", nrow(memory))
  add_metric("memory_tombstoned", sum(tolower(memory$tombstone) == "true", na.rm = TRUE))
  add_metric("memory_mean_salience", round(mean(memory$salience, na.rm = TRUE), 3))

  png_open(file.path(out_dir, "memory_salience.png"), height = 600)
  graphics::hist(
    memory$salience,
    breaks = 10,
    col = "#805ad5",
    border = "white",
    main = "Memory salience distribution",
    xlab = "salience"
  )
  png_close()
}

if (!is.null(payments)) {
  add_metric("payments_count", nrow(payments))
  add_metric("payments_total_cents", sum(payments$amount_cents, na.rm = TRUE))

  totals <- tapply(payments$amount_cents / 100, payments$payee, sum)
  totals <- totals[order(-totals)]
  png_open(file.path(out_dir, "payments_by_payee.png"), height = 600)
  graphics::barplot(
    totals,
    las = 2,
    cex.names = 0.8,
    col = "#2c7a7b",
    main = "Settled payments by payee",
    ylab = "amount (major units)"
  )
  png_close()
}

if (!is.null(audit)) {
  add_metric("audit_entries", nrow(audit))
  kinds <- sort(table(audit$kind), decreasing = TRUE)
  utils::write.csv(
    data.frame(kind = names(kinds), entries = as.integer(kinds)),
    file.path(out_dir, "audit_kinds.csv"),
    row.names = FALSE
  )

  png_open(file.path(out_dir, "audit_kinds.png"), height = 600)
  graphics::barplot(
    kinds,
    las = 2,
    cex.names = 0.8,
    col = "#4a5568",
    main = "Audit entries by kind",
    ylab = "entries"
  )
  png_close()
}

if (!is.null(stealth) && nrow(stealth) > 0) {
  add_metric("stealth_cells", nrow(stealth))
  add_metric("stealth_wire_bytes", paste(unique(stealth$wire_bytes), collapse = "/"))
  add_metric("stealth_uniform", length(unique(stealth$wire_bytes)) == 1)
  add_metric("stealth_cover_pct", pct(sum(stealth$kind == "cover"), nrow(stealth)))
  add_metric("stealth_mean_jitter_ms", round(mean(stealth$jitter_ms), 1))
  utils::write.csv(stealth, file.path(out_dir, "stealth_cells.csv"), row.names = FALSE)

  png_open(file.path(out_dir, "stealth_jitter.png"), height = 600)
  graphics::barplot(
    stealth$jitter_ms,
    names.arg = stealth$index,
    col = ifelse(stealth$kind == "cover", "grey75", "#1f77b4"),
    border = NA,
    main = "Stealth cells: jitter per cell, every cell the same size",
    xlab = "cell index",
    ylab = "jitter (ms)"
  )
  graphics::legend(
    "topright",
    legend = c("data", "cover"),
    fill = c("#1f77b4", "grey75"),
    border = NA
  )
  png_close()
}

if (!is.null(prediction) && nrow(prediction) > 0) {
  scored <- prediction[!is.na(prediction$observed), ]
  add_metric("prediction_rows", nrow(prediction))
  if (nrow(scored) > 0) {
    add_metric("prediction_mae", round(mean(abs(scored$error)), 4))
    add_metric("prediction_rmse", round(sqrt(mean(scored$error^2)), 4))
    add_metric("prediction_series", nrow(scored))
    utils::write.csv(scored, file.path(out_dir, "prediction_scored.csv"), row.names = FALSE)
    png_open(file.path(out_dir, "prediction_error.png"), height = 600)
    graphics::barplot(
      abs(scored$error),
      names.arg = scored$series,
      col = "#dd6b20",
      border = NA,
      main = "Prediction error against a real reading",
      ylab = "absolute error"
    )
    png_close()
  }
}

if (!is.null(layers) && nrow(layers) > 0) {
  add_metric("layers", nrow(layers))
  utils::write.csv(layers, file.path(out_dir, "layers.csv"), row.names = FALSE)
}

if (!is.null(image_quality) && nrow(image_quality) > 0) {
  numeric_rows <- image_quality[image_quality$metric %in% c(
    "contrast", "saturation", "edge_energy", "unique_colours", "std_luminance"
  ), ]
  for (i in seq_len(nrow(numeric_rows))) {
    add_metric(paste0("image_", numeric_rows$metric[i]), as.numeric(numeric_rows$value[i]))
  }
}

utils::write.csv(metrics, file.path(out_dir, "metrics.csv"), row.names = FALSE)

cat("OmniShield analysis\n")
for (i in seq_len(nrow(metrics))) {
  cat(sprintf("  %-22s %s\n", metrics$metric[i], metrics$value[i]))
}
cat(sprintf("wrote tables and charts to %s\n", out_dir))
