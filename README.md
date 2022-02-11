# Python 3

## Installation

### All Platforms
Run the following to install the latest from PyPi
```bash
pip install pyshark
```

Or install from the git repository:
```bash
git clone https://github.com/KimiNewt/pyshark.git
cd pyshark/src
python setup.py install
```

### Mac OS X
You may have to install libxml which can be unexpected.  If you receive an error from clang or an error message about libxml, run the following:
```bash
xcode-select --install
pip install libxml
```

## Usage

```bash
python src/pcap_analysis.py pcap_files/original-file.pcap anon_files/anonymized-file.pcap 
```
