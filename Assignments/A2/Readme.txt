Hannah Bishop
V00805425
CSC361 Spring 2018 Assignment #2

#Description
tcp.py is a command line tool that analyzes packet information from a tcp capture file

#Run
To run the program:
    $ python3 tcp.py <tcp_file_name>
For example:
    $ python3 tcp.py sample-capture-file
    
    or 

    $python3 tcp.py trace.cap

#Requirements
This program uses the dpkt module. Information about dpkt can be found here:

http://dpkt.readthedocs.io/en/latest/index.html

Install dpkt using:

    $ pip install dpkt

Or, use the requirements.txt file to download requirements:

    $ pip install -r requirements.txt

#Other information
This program was built to run using Python3.6 and higher.
