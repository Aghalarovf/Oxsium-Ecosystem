_dataset = None


def get_dataset():
    return _dataset


def load_dataset(data):
    global _dataset
    _dataset = data
    return _dataset
