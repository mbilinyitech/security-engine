# Check the MLP training curve independently from the CSV.
args <- commandArgs(trailingOnly = TRUE)
root <- if (length(args) >= 1) args[1] else "analysis/data/mlp"
path <- file.path(root, "mlp.csv")
if (!file.exists(path)) stop("no mlp.csv in ", root)
curve <- read.csv(path, stringsAsFactors = FALSE)
first <- curve$loss[1]
last <- curve$loss[nrow(curve)]
best <- max(curve$accuracy)
if (!(last < first)) stop("the loss did not fall")
if (best < 1) stop("the network did not learn XOR")
cat(sprintf("epochs: %d\n", nrow(curve)))
cat(sprintf("loss: %.6f -> %.6f (drop %.2f%%)\n", first, last, 100 * (first - last) / first))
cat(sprintf("best accuracy: %.2f\n", best))
cat("mlp converged\n")
