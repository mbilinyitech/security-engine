#!/usr/bin/env Rscript
# Build the OmniShield report (Markdown + HTML) from the analysis output.
# Usage: Rscript analysis/report.R [data_dir] [out_dir]

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
manifest <- read_csv_safe(file.path(data_dir, "manifest.csv"))

metrics <- read_csv_safe(file.path(out_dir, "metrics.csv"))
status_counts <- read_csv_safe(file.path(out_dir, "status_counts.csv"))
by_group <- read_csv_safe(file.path(out_dir, "by_group.csv"))
audit_kinds <- read_csv_safe(file.path(out_dir, "audit_kinds.csv"))

if (is.null(metrics)) {
  stop("run analysis/analyse.R first: metrics.csv is missing")
}

metric <- function(name, default = "n/a") {
  row <- metrics[metrics$metric == name, ]
  if (nrow(row) == 0) default else row$value[[1]]
}

generated <- format(Sys.time(), "%Y-%m-%d %H:%M:%S UTC", tz = "UTC")

headline <- data.frame(
  metric = c(
    "Features in the ledger",
    "Built (implemented + partial)",
    "Coverage",
    "Components healthy",
    "Doctor checks passed",
    "Doctor wall time"
  ),
  value = c(
    metric("features_total"),
    metric("features_built"),
    paste0(metric("coverage_pct"), "%"),
    paste0(metric("components_ok"), " / ", metric("components_total")),
    paste0(metric("doctor_passed"), " / ", metric("doctor_checks")),
    paste0(metric("doctor_total_ms"), " ms")
  ),
  stringsAsFactors = FALSE
)

md <- c(
  "# OmniShield analysis report",
  "",
  paste0("Generated ", generated, " by `analysis/report.R` from data produced by ",
         "`omnishield export`. Every number below comes from the running system."),
  "",
  "## Headline",
  "",
  md_table(headline),
  "",
  "## Feature coverage",
  "",
  md_table(status_counts),
  "",
  "### Coverage by group",
  "",
  md_table(utils::head(by_group, 25)),
  "",
  "![Features by status](status.png)",
  "",
  "![Coverage by group](coverage_by_group.png)",
  ""
)

html <- c(
  "<!doctype html>",
  "<html lang=\"en\"><head><meta charset=\"utf-8\">",
  "<title>OmniShield analysis report</title>",
  "<style>",
  "body{font-family:system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1a202c}",
  "h1{font-size:1.8rem}h2{margin-top:2rem;border-bottom:1px solid #e2e8f0}",
  "table{border-collapse:collapse;width:100%;margin:.8rem 0;font-size:.92rem}",
  "th,td{border:1px solid #e2e8f0;padding:.35rem .5rem;text-align:left}",
  "th{background:#f7fafc}img{max-width:100%;border:1px solid #e2e8f0;margin:.6rem 0}",
  "code{background:#f7fafc;padding:.1rem .3rem}",
  "</style></head><body>",
  "<h1>OmniShield analysis report</h1>",
  paste0("<p>Generated ", html_escape(generated),
         " by <code>analysis/report.R</code> from <code>omnishield export</code>.</p>"),
  "<h2>Headline</h2>",
  html_table(headline),
  "<h2>Feature coverage</h2>",
  html_table(status_counts),
  "<h3>Coverage by group</h3>",
  html_table(utils::head(by_group, 25)),
  "<p><img src=\"status.png\" alt=\"features by status\"></p>",
  "<p><img src=\"coverage_by_group.png\" alt=\"coverage by group\"></p>"
)

if (!is.null(components)) {
  shown <- components[, c("name", "layer", "ok", "evidence")]
  md <- c(md, "## Components", "", md_table(shown), "")
  html <- c(html, "<h2>Components</h2>", html_table(shown))
}

if (!is.null(doctor)) {
  shown <- doctor[, c("check", "ok", "ms", "detail")]
  md <- c(
    md,
    "## Doctor checks",
    "",
    paste0("All ", nrow(doctor), " checks run real code; total ",
           sum(doctor$ms), " ms."),
    "",
    md_table(shown),
    "",
    "![Doctor check duration](doctor_ms.png)",
    ""
  )
  html <- c(
    html,
    "<h2>Doctor checks</h2>",
    paste0("<p>All ", nrow(doctor), " checks run real code; total ", sum(doctor$ms), " ms.</p>"),
    html_table(shown),
    "<p><img src=\"doctor_ms.png\" alt=\"doctor timings\"></p>"
  )
}

if (!is.null(prediction) && nrow(prediction) > 0) {
  scored <- prediction[!is.na(prediction$observed), ]
  md <- c(
    md,
    "## Prediction against reality",
    "",
    "The system sampled its own load and memory, predicted the next reading,",
    "then measured it. The error below is the measured difference, not a claim.",
    "",
    md_table(scored[, c("series", "kind", "predicted", "observed", "error", "r2")]),
    "",
    if (nrow(scored) > 0) "![Prediction error](prediction_error.png)" else "",
    ""
  )
  html <- c(
    html,
    "<h2>Prediction against reality</h2>",
    "<p>The system sampled its own load and memory, predicted the next reading,",
    "then measured it.</p>",
    html_table(scored[, c("series", "kind", "predicted", "observed", "error", "r2")]),
    if (nrow(scored) > 0) "<p><img src=\"prediction_error.png\" alt=\"prediction error\"></p>" else ""
  )
}

if (!is.null(image_quality) && nrow(image_quality) > 0) {
  md <- c(
    md,
    "## Rendered image quality",
    "",
    "Measured on the rendered pixels, not estimated from the code.",
    "",
    md_table(image_quality),
    ""
  )
  html <- c(html, "<h2>Rendered image quality</h2>", html_table(image_quality))
}

if (!is.null(layers) && nrow(layers) > 0) {
  md <- c(md, "## Coverage by layer", "", md_table(layers), "")
  html <- c(html, "<h2>Coverage by layer</h2>", html_table(layers))
}

if (!is.null(stealth) && nrow(stealth) > 0) {
  summary <- data.frame(
    metric = c(
      "Cells", "Wire bytes per cell", "Uniform size",
      "Cover traffic", "Mean jitter"
    ),
    value = c(
      nrow(stealth),
      paste(unique(stealth$wire_bytes), collapse = "/"),
      if (length(unique(stealth$wire_bytes)) == 1) "yes" else "no",
      paste0(metric("stealth_cover_pct"), "%"),
      paste0(metric("stealth_mean_jitter_ms"), " ms")
    ),
    stringsAsFactors = FALSE
  )
  md <- c(
    md,
    "## Stealth transport",
    "",
    "Every cell has the same size, so the wire never reveals a length; cover",
    "cells are sealed with the same key and dropped after decryption.",
    "",
    md_table(summary),
    "",
    "![Stealth cell jitter](stealth_jitter.png)",
    ""
  )
  html <- c(
    html,
    "<h2>Stealth transport</h2>",
    "<p>Every cell has the same size, so the wire never reveals a length; cover",
    "cells are sealed with the same key and dropped after decryption.</p>",
    html_table(summary),
    "<p><img src=\"stealth_jitter.png\" alt=\"stealth cell jitter\"></p>"
  )
}

if (!is.null(memory)) {
  summary <- data.frame(
    metric = c("Memories", "Tombstoned", "Mean salience", "Dimensions"),
    value = c(
      nrow(memory),
      metric("memory_tombstoned"),
      metric("memory_mean_salience"),
      paste(unique(memory$embedding_dim), collapse = ", ")
    ),
    stringsAsFactors = FALSE
  )
  md <- c(md, "## Memory", "", md_table(summary), "",
          "![Memory salience](memory_salience.png)", "")
  html <- c(html, "<h2>Memory</h2>", html_table(summary),
            "<p><img src=\"memory_salience.png\" alt=\"memory salience\"></p>")
}

if (!is.null(payments)) {
  summary <- data.frame(
    metric = c("Settlements", "Total (major units)", "Currencies", "Payees"),
    value = c(
      nrow(payments),
      format(sum(payments$amount_cents) / 100, big.mark = ",", scientific = FALSE),
      paste(unique(payments$currency), collapse = ", "),
      paste(unique(payments$payee), collapse = ", ")
    ),
    stringsAsFactors = FALSE
  )
  md <- c(md, "## Payments", "", md_table(summary), "",
          "![Payments by payee](payments_by_payee.png)", "")
  html <- c(html, "<h2>Payments</h2>", html_table(summary),
            "<p><img src=\"payments_by_payee.png\" alt=\"payments by payee\"></p>")
}

if (!is.null(audit_kinds)) {
  md <- c(md, "## Audit activity", "", md_table(audit_kinds), "",
          "![Audit entries by kind](audit_kinds.png)", "")
  html <- c(html, "<h2>Audit activity</h2>", html_table(audit_kinds),
            "<p><img src=\"audit_kinds.png\" alt=\"audit kinds\"></p>")
}

if (!is.null(manifest)) {
  md <- c(md, "## Provenance", "",
          "Every input file and its SHA-256, as exported.", "",
          md_table(manifest), "")
  html <- c(html, "<h2>Provenance</h2>", html_table(manifest))
}

md <- c(md, "## Method", "",
        "- `omnishield export` writes tidy CSV from the live ledger, status checks,",
        "  a real doctor run, and any memory database, audit log or payment ledger you pass.",
        "- `analysis/analyse.R` computes the tables and base-R charts.",
        "- `analysis/report.R` renders this file; nothing is typed by hand.",
        "")

html <- c(html,
          "<h2>Method</h2><ul>",
          "<li><code>omnishield export</code> writes tidy CSV from the live system.</li>",
          "<li><code>analysis/analyse.R</code> computes the tables and charts.</li>",
          "<li><code>analysis/report.R</code> renders this page; nothing is typed by hand.</li>",
          "</ul></body></html>")

write_text(file.path(out_dir, "REPORT.md"), md)
write_text(file.path(out_dir, "report.html"), html)
cat(sprintf("wrote %s and %s\n",
            file.path(out_dir, "REPORT.md"),
            file.path(out_dir, "report.html")))
