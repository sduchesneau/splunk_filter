from ConfigParser import SafeConfigParser

class config_item(object):
    """
    Turns a dictionary into an object accessible through "a.b" 
    (only one level)
    """
    def __init__(self, d):
        self.__dict__ = d

class ParseConfig(object):
    """
    Reads a config file and return two-levels of flat object:
    my_object.config_section.config_param
    """
    def __init__(self, *file_names):
        parser = SafeConfigParser()
        found = parser.read(file_names)
        if not found:
            raise ValueError('No config file found!')
        for name in parser.sections():
            myDict={}
            myDict.update(parser.items(name))
            self.__dict__[name] = (config_item(myDict)) # add to object's dict

config = ParseConfig('splunk_filter.conf')