class Record:
    def __init__(self, text, action=None, *args, **kwargs):
        self.text = text
        assert action in ['INFO', 'WARNING', 'CRITICAL', None]
        self.action = action
        self.params = kwargs

    def __getattr__(self, item):
        if item in self.params:
            return self.params[item]
        print("No attribute %s, safely returned None" % item)
        # raise AttributeError()

    def show(self):
        pass

    def hide(self):
        pass
