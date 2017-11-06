# -*- coding: utf-8 -*-

"""Main module."""

import requests

typeid = {'1': 'A',
          '2': 'NS',
          '28': 'AAAA',
          '18': 'AFSDB',
          '42': 'APL',
          '15': 'MX',
          '12': 'PTR',
          '33': 'SRV',
          '16': 'TXT',
          '45': 'IPSECKEY',
          '6': 'SOA',
          '5': 'CNAME',
          '257': 'CAA',
          '99': 'SPF', }


def main():
    domain = raw_input('Please enter domain: ')
    record = raw_input('Please enter record type: ')
    # parameter digg domain google.com type ANY

    base_api = 'https://dns.google.com/resolve?name=' + domain + '&type=' + record # noqa

    r = requests.get(base_api)
    data = r.json()
    answers = []

    for r in data.get('Answer'):
        r['typeName'] = typeid[str(r['type'])]
        answers.append(r)

    data['Answer'] = answers
    print(data)


if __name__ == '__main__':
    main()
