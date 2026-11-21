# Shared helpers for the OmniShield analysis pipeline.
# Base R only: no packages to install.

read_csv_safe <- function(path) {
  if (!file.exists(path)) {
    return(NULL)
  }
  tryCatch(
    utils::read.csv(
      path,
      stringsAsFactors = FALSE,
      check.names = FALSE,
      na.strings = c("", "NA")
    ),
    error = function(e) NULL
  )
}

script_dir <- function(fallback = "analysis") {
  flags <- grep("^--file=", commandArgs(trailingOnly = FALSE), value = TRUE)
  if (length(flags) == 0) {
    return(fallback)
  }
  dirname(normalizePath(sub("^--file=", "", flags[[1]])))
}

pct <- function(n, d) {
  ifelse(is.na(d) | d == 0, 0, round(100 * n / d, 1))
}

fmt_num <- function(x, digits = 1) {
  if (is.numeric(x)) {
    format(round(x, digits), big.mark = ",", scientific = FALSE, trim = TRUE)
  } else {
    as.character(x)
  }
}

md_table <- function(df, digits = 1) {
  if (is.null(df) || nrow(df) == 0) {
    return("_(no rows)_")
  }
  df[] <- lapply(df, fmt_num, digits = digits)
  header <- paste0("| ", paste(names(df), collapse = " | "), " |")
  rule <- paste0("|", paste(rep("---", ncol(df)), collapse = "|"), "|")
  body <- apply(df, 1, function(row) {
    paste0("| ", paste(row, collapse = " | "), " |")
  })
  paste(c(header, rule, body), collapse = "\n")
}

html_escape <- function(x) {
  x <- gsub("&", "&amp;", x, fixed = TRUE)
  x <- gsub("<", "&lt;", x, fixed = TRUE)
  gsub(">", "&gt;", x, fixed = TRUE)
}

html_table <- function(df, digits = 1) {
  if (is.null(df) || nrow(df) == 0) {
    return("<p><em>no rows</em></p>")
  }
  df[] <- lapply(df, fmt_num, digits = digits)
  head <- paste0(
    "<tr>",
    paste0("<th>", html_escape(names(df)), "</th>", collapse = ""),
    "</tr>"
  )
  rows <- apply(df, 1, function(row) {
    paste0("<tr>", paste0("<td>", html_escape(row), "</td>", collapse = ""), "</tr>")
  })
  paste0("<table>", head, paste(rows, collapse = ""), "</table>")
}

write_text <- function(path, lines) {
  writeLines(lines, con = path, useBytes = TRUE)
}

png_open <- function(path, width = 1100, height = 650) {
  grDevices::png(path, width = width, height = height, res = 110)
  graphics::par(mar = c(4, 4, 3, 1))
}

png_close <- function() {
  grDevices::dev.off()
}
