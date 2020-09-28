import logging

LOGGER = logging.getLogger(__name__)


class Report():
    def __init__(self):
        self.items = []

    def append(self, *items):
        self.items.append(' '.join(map(str, items)))

    def print_report(self):
        for item in self.items:
            LOGGER.info(str(item))
            # import pdb; pdb.set_trace()
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(item))

    def get_str(self):
        return '\n'.join(map(str, self.items))


