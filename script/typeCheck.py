import json

bypass = [10, 11, 12]
with open('./result.json', 'r') as target:
    b = json.load(target)
    a = list()
    for i in range(4096):
        a.append(7)

    for record in b:
        a[record['Hash']] = record['Attribute']['TypeCode']

    with open('./typeTable.json', 'r') as srcfile:
        src = json.load(srcfile)
        for i in range(4096):
            if src[i] not in bypass and src[i] != a[i]:
                print('{} [{},{}]'.format(i, src[i], a[i]))
