from publicsuffix2 import get_sld


def main_domain(name):
    """Registrable domain of a host name: www.example.co.uk -> example.co.uk.

    Names under a TLD the public suffix list doesn't know (internal ones like .lan) fall back to the last two labels.
    """
    name = name.rstrip('.').lower()
    sld = get_sld(name)
    if sld and '.' in sld:
        return sld
    labels = name.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else name
