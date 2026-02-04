from tensorflow.keras.models import load_model
model = load_model("model/banana_cnn_multi_model.h5")
print(model.input_shape)
