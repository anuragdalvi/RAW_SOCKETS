Approach and Challenges:
1) We implemented Object Oriented approach in creating headers for TCP and IP,
The challenge was to change the information in TCP headers everytime a new
packet is sent. In order to change the TCP information in TCP headers by changing values of
attributes of the object created.

2) Another challenge was to parse the TCP headers in order to extract the
information from the TCP headers and use the information to create new
responses. We created another class to parse the information received in TCP
headers and used those objects that parse the information as arguments to
functions to create packets.

3) Another class was introduced using objects created from above classes. The
functions of this class would send syn, ack and send data by changing attributes
of the objects created from above classes.

4) In the main part of the code we used the objects created from above classes to
manage the requests, acks and data from the server.

5) In order to maintain the sequence of the data received we used dictionary
keys as the sequence numbers and data received corresponding to the
sequence numbers and sorted the dictionary.

6) From the HTTP reponse that we received we checked the status code using the
above functions and would only continue with the code only if it is
200 OK.

7) We set the initial congestion window to 1 and subthreshold to 1000 and
initiated the time at which ack was sent.

8) We also modify congestion window with every successful ack we receive and
reduce it to 1 for every packet drop. Also if we dont receive over 3 mins the
code exits.

7) Our condition to exit the code is when we get a fIN/ACK

