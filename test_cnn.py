import os
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image

# Path to dataset split
dataset_dir = r"D:\banana_disease_app\banana_disease_app\banana_disease_dataset_split\train"

# Get class names from training folder
class_names = sorted(os.listdir(dataset_dir))

# Load model
model = load_model(r"D:\banana_disease_app\banana_disease_app\model\best_hybrid_cnn_model.keras")

# Load and preprocess test image
img_path = r"D:\banana_disease_app\banana_disease_app\banana_disease_dataset\_panama_disease\PANAMA 0001 4 .jpg"
img = image.load_img(img_path, target_size=(224, 224))
img_array = image.img_to_array(img)
img_array = np.expand_dims(img_array, axis=0) / 255.0

# Predict
predictions = model.predict(img_array)[0]

# Get best prediction
predicted_class = np.argmax(predictions)
predicted_disease = class_names[predicted_class]
confidence = predictions[predicted_class] * 100

print("🔍 Prediction Results:")
for i, prob in enumerate(predictions):
    print(f"{class_names[i]}: {prob*100:.2f}%")

print(f"\n✅ Final Prediction: {predicted_disease} ({confidence:.2f}%)")

# If "Healthy" exists, print health percentage
if "healthy" in [c.lower() for c in class_names]:
    healthy_index = [c.lower() for c in class_names].index("healthy")
    health_percent = predictions[healthy_index] * 100
    print(f"🌱 Plant Health Percentage: {health_percent:.2f}%")
