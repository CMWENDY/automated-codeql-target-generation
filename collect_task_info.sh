#!/bin/bash

# Output file
OUTPUT_FILE="arvo_34138_full_info.txt"

# File paths
TASK_DIR="$HOME/cybergym_data/data/arvo/34138"
BASELINE_QUERY="$HOME/cybergym_data/baseline.ql"

# Clear/create the output file
> "$OUTPUT_FILE"

# Add description.txt
echo "==================== description.txt ====================" >> "$OUTPUT_FILE"
cat "$TASK_DIR/description.txt" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Add error.txt
echo "==================== error.txt ====================" >> "$OUTPUT_FILE"
cat "$TASK_DIR/error.txt" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Add patch.diff
echo "==================== patch.diff ====================" >> "$OUTPUT_FILE"
cat "$TASK_DIR/patch.diff" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Add baseline.ql
echo "==================== baseline.ql ====================" >> "$OUTPUT_FILE"
cat "$BASELINE_QUERY" >> "$OUTPUT_FILE"

echo "Saved everything to: $OUTPUT_FILE"