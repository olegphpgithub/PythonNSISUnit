import os
import glob
import argparse
from os import listdir

patterns = dict([(br'd:\\qt\\openssl\\openssl-1.0.1u-vs2015-static-x32\\lib', br'$$[QT_INSTALL_LIBS]'),
                 (br'qt_instdate=2021-11-23', None),
                 (br'qt_prfxpath=d:/qt/5.3.2.0.a', None),
                 (br'qt_docspath=d:/qt/5.3.2.0.a/doc', None),
                 (br'qt_hdrspath=d:/qt/5.3.2.0.a/include', None),
                 (br'qt_libspath=d:/qt/5.3.2.0.a/lib', None),
                 (br'qt_lbexpath=d:/qt/5.3.2.0.a/bin', None),
                 (br'qt_binspath=d:/qt/5.3.2.0.a/bin', None),
                 (br'qt_plugpath=d:/qt/5.3.2.0.a/plugins', None),
                 (br'qt_impspath=d:/qt/5.3.2.0.a/imports', None),
                 (br'qt_qml2path=d:/qt/5.3.2.0.a/qml', None),
                 (br'qt_adatpath=d:/qt/5.3.2.0.a', None),
                 (br'qt_datapath=d:/qt/5.3.2.0.a', None),
                 (br'qt_trnspath=d:/qt/5.3.2.0.a/translations', None),
                 (br'qt_xmplpath=d:/qt/5.3.2.0.a/examples', None),
                 (br'qt_demopath=d:/qt/5.3.2.0.a/demos', None),
                 (br'qt_tstspath=d:/qt/5.3.2.0.a/tests', None),
                 (br'a1961a20-ab24-4c4e-a64b-d579266dbed8', None)
])

def substitute_file(file_name):
    with open(file_name, 'rb') as file:
        file_data = file.read()

    for pattern_key in patterns.keys():
        pattern_value = patterns[pattern_key]
        if pattern_value is None:
            placeholder = b''.join(b'\x00' for _ in pattern_key)
        else:
            placeholder = pattern_value
        file_data = file_data.replace(pattern_key, placeholder)

    with open(file_name, 'wb') as file:
        file.write(file_data)

    print(r'%s - %s' % (file_name, r'processed'))


def substitute_recursively(directory_name, extension_list):
    for extension in extension_list:
        for file_name in glob.glob('%s%s%s' % (directory_name, os.sep, extension)):
            if os.path.isfile(file_name):
                substitute_file(file_name)

    for file_name in listdir(directory_name):
        if os.path.isdir(os.path.join(directory_name, file_name)):
            substitute_recursively(os.path.join(directory_name, file_name), extension_list)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-directory', required=True)
    args = parser.parse_args()

    if not os.path.isdir(args.source_directory):
        print("Source directory \"%s\" does not exist" % args.source_directory)
        exit(1)

    extensions = [r'*.lib', r'*.prl']

    substitute_recursively(args.source_directory, extensions)
