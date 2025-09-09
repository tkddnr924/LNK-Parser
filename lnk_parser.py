import argparse
import ms_shell_link

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LNK parser')
    parser.add_argument('lnk_path', metavar='lnk_path', type=str,)
    args = parser.parse_args()

    ms_shell_link.parse_lnk(args.lnk_path)