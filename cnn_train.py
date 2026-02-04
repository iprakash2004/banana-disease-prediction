from tensorflow.keras.preprocessing.image import ImageDataGenerator

train_dir = "D:/banana_disease_app/banana_disease_app/banana_disease_dataset_split/train"
test_dir = "D:/banana_disease_app/banana_disease_app/banana_disease_dataset_split/test"

train_datagen = ImageDataGenerator(
    rescale=1./255,
    rotation_range=20,
    width_shift_range=0.1,
    height_shift_range=0.1,
    shear_range=0.1,
    zoom_range=0.1,
    horizontal_flip=True,
    fill_mode='nearest'
)

test_datagen = ImageDataGenerator(rescale=1./255)

train_generator = train_datagen.flow_from_directory(
    train_dir,
    target_size=(224,224),
    batch_size=32,
    class_mode='categorical'
)

test_generator = test_datagen.flow_from_directory(
    test_dir,
    target_size=(224,224),
    batch_size=32,
    class_mode='categorical',
    shuffle=False
)

# Now you can get number of classes
num_classes = len(train_generator.class_indices)
print(f"Number of classes: {num_classes}")
