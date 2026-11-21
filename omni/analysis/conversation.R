# Conversation and answer analysis over the CSVs written by omnishield r export.
# Every number comes from the rows; nothing is modelled.

args <- commandArgs(trailingOnly = TRUE)
root <- if (length(args) >= 1) args[1] else "analysis/data"
out <- file.path(root, "conversation-report.txt")

conv_path <- file.path(root, "conversation.csv")
ans_path <- file.path(root, "answers.csv")
if (!file.exists(conv_path)) stop("no conversation.csv in ", root)
conv <- read.csv(conv_path, stringsAsFactors = FALSE)

lines <- nrow(conv)
speakers <- length(unique(conv$speaker))
langs <- sort(table(conv$language), decreasing = TRUE)
lang_share <- round(100 * as.numeric(langs) / lines, 2)
mean_conf <- round(mean(conv$confidence), 4)
mean_drift <- round(mean(conv$drift), 4)
max_drift <- round(max(conv$drift), 4)

terms <- unlist(strsplit(conv$terms, "|", fixed = TRUE))
terms <- terms[nzchar(terms)]
top_terms <- head(sort(table(terms), decreasing = TRUE), 8)

report <- c(
  "Conversation report",
  "===================",
  sprintf("lines: %d", lines),
  sprintf("speakers: %d", speakers),
  sprintf("mean confidence: %.4f", mean_conf),
  sprintf("mean drift: %.4f  max drift: %.4f", mean_drift, max_drift),
  "languages:",
  sprintf("  %s: %d (%.2f%%)", names(langs), as.integer(langs), lang_share),
  "top terms:",
  sprintf("  %s: %d", names(top_terms), as.integer(top_terms))
)

if (file.exists(ans_path)) {
  ans <- read.csv(ans_path, stringsAsFactors = FALSE)
  lat <- ans$latency_ms
  report <- c(
    report,
    "answers:",
    sprintf("  questions: %d", nrow(ans)),
    sprintf("  confidence mean: %.4f", round(mean(ans$confidence), 4)),
    sprintf("  citations mean: %.2f", round(mean(ans$citations), 2)),
    sprintf("  latency ms: mean %.3f  median %.3f  p90 %.3f", round(mean(lat), 3), round(median(lat), 3), round(quantile(lat, 0.9), 3)),
    sprintf("  sources: %s", paste(names(sort(table(unlist(strsplit(ans$sources, "|", fixed = TRUE))), decreasing = TRUE)), collapse = ", "))
  )
}

writeLines(report, out)
cat(paste(report, collapse = "\n"), "\n")
cat("wrote", out, "\n")
