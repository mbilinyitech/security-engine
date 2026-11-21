# Verify the neuron arithmetic independently: read the CSV, recompute the dot
# product from x and w, and compare it with what Python and Rust reported.

args <- commandArgs(trailingOnly = TRUE)
root <- if (length(args) >= 1) args[1] else "analysis/data/neuron"
path <- file.path(root, "neuron.csv")
if (!file.exists(path)) stop("no neuron.csv in ", root)
rows <- read.csv(path, stringsAsFactors = FALSE)

recomputed <- sum(rows$x * rows$w)
python <- rows$python_dot[1]
rust <- rows$rust_dot[1]
diff_python <- abs(recomputed - python)
diff_rust <- abs(recomputed - rust)
sigmoid <- 1 / (1 + exp(-(recomputed + 0.1)))

cat(sprintf("rows: %d\n", nrow(rows)))
cat(sprintf("recomputed dot: %.12f\n", recomputed))
cat(sprintf("python dot:     %.12f (diff %.2e)\n", python, diff_python))
cat(sprintf("rust dot:       %.12f (diff %.2e)\n", rust, diff_rust))
cat(sprintf("sigmoid:        %.12f\n", sigmoid))
if (diff_python > 1e-9 || diff_rust > 1e-9) stop("the dot products disagree")
cat("all three agree\n")
