#!/usr/bin/python3
class test(object):
    def __init__(self) -> None:
        super().__init__()
        self.name = '111'
    def get_name(self):
        print(self.name)
if __name__ == '__main__':
    t = test()
    t.get_name()