#!/bin/bash

DIR_TO_COMPRESS="firstdir"
BASE_NAME="kfArchiveTest"
ZIP_FILE="template.zip"

# Extract template.zip
if [ -f "$ZIP_FILE" ]; then
    # Remove the __MACOSX directory if it exists
    rm -rf __MACOSX

    unzip "$ZIP_FILE"
    find . -name ".*" -exec rm -rf {} +
    rm -rf __MACOSX
else
    echo "Error: $ZIP_FILE not found."
    exit 1
fi
sleep 2

# Create archives in different formats
7z a -tzip "${BASE_NAME}.zip" "$DIR_TO_COMPRESS/"
7z a -tzip "${BASE_NAME}_zip_inside.zip" "${BASE_NAME}.zip"
7z a -ttar "${BASE_NAME}.tar" "$DIR_TO_COMPRESS/"
7z a -tgzip "${BASE_NAME}.tar.gz" "${BASE_NAME}.tar"
7z a -tbzip2 "${BASE_NAME}.tar.bz2" "${BASE_NAME}.tar"
7z a -txz "${BASE_NAME}.tar.xz" "${BASE_NAME}.tar"
7z a -tlz4 "${BASE_NAME}.tar.lz4" "${BASE_NAME}.tar"
7z a -t7z "${BASE_NAME}.7z" "$DIR_TO_COMPRESS/"
7z a -tgzip "${BASE_NAME}.gz" "$DIR_TO_COMPRESS/"
7z a -tbzip2 "${BASE_NAME}.bz2" "$DIR_TO_COMPRESS/"
7z a -txz "${BASE_NAME}.xz" "$DIR_TO_COMPRESS/"

# Create RAR archive if rar command is available
if command -v rar >/dev/null 2>&1; then
    rar a -r "${BASE_NAME}.rar" "$DIR_TO_COMPRESS/"
else
    echo "rar command not found. Skipping .rar archive creation."
fi

rm -rf "$DIR_TO_COMPRESS"
echo "Compression complete."
