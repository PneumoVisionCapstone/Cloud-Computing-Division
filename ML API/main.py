from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import img_to_array
import numpy as np
import io
from PIL import Image
import os

app = FastAPI()

# Memuat model saat aplikasi dimulai
model_path = "model/model_capstone.h5"
model = load_model(model_path)

@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        # Baca file yang diunggah langsung dari memori
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))

        # Ubah mode gambar ke RGB jika tidak dalam mode RGB
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Lakukan preprocessing pada gambar
        image = image.resize((150, 150))  # Sesuaikan dengan ukuran input model Anda
        image = img_to_array(image)
        image = np.expand_dims(image, axis=0)
        image = image / 255.0  # Normalisasi jika diperlukan

        # Lakukan prediksi
        predictions = model.predict(image)
        predicted_class = np.argmax(predictions, axis=1)

        return JSONResponse(content={ "probabilities": predictions.tolist()})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
    
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))  # Default to 3000 if PORT is not set
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
