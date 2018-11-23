# pcap_preprocessing
Scripts to extract packet features from pcap files and generate arffs for AI purposes

These files help the extraction of packet features from pcap files. Specifically:

1) Convert the pcap file to pdml 
2) Run the pdml2arff.py (you can customise the script to pull out the features that you need)
3) If you have multiple arff files in the end, you can use arffmerger.py to combine them all in one
