import base64
import os

png_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
png_data = base64.b64decode(png_base64)

os.makedirs('extension/icons', exist_ok=True)
for size in [16, 48, 128]:
    with open(f'extension/icons/icon{size}.png', 'wb') as f:
        f.write(png_data)
