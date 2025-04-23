# Standard Operating Procedure: Suricata Rule Development

## Objective

The Objective of this Standard Operating Procedure aimed to learn and understand the syntax and behavior of Suricata rules, in order to learn how to read them, and how to develop them based on provided data.

### Skills Learned

- Suricata Rule Development

### Tools Used

- <a href="https://suricata.io/">Suricata</a> (open source Intrusion Detection System and Intrusion Prevention System) 
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.

## Application

All SOC analysts can apply these steps to minimize confusion over Suricata rules, and minimize errors when creating new ones.

## Overview of Suricata rules: 

Suricata rules are made up of 5 parts: The action, the header, the rule message, the rule content, and the rule metadata. An example of a rule is as follows:

![image](https://github.com/user-attachments/assets/8c48064f-03a8-410a-bb0c-0bd151cb56f5)


- The $${\color{red}action}$$: This informs Suricata on what steps to take if the contents found match the content of the rule.  Suricata rules can vary from generating an alert, logging the traffic without an alert, ignoring the packet, dropping the packet, or sending RST(reject) packets.
- The $${\color{green}header}$$: The header defines the protocol, ip addresses, ports and direction of the rule (action protocol from_ip port -> to_ip port)
- The rule $${\color{lightblue}message}$$: Arbitrary text to be displayed when the rule is triggered to provide context for the analyst receiving it
- The rule $${\color{blue}content}$$: The content further specifies of the rule to make it’s detection more accurate. It can include segments of the traffic that are considered essential for such detections, or further filters or definitions for the rule to narrow down the type of traffic that applies to it.
- The rule $${\color{purple}metadata}$$: The footnote of a rule that contains the sid(signature ID), rev(revision), and potentially the reference. The sid is used as a unique numeric identifier to distinguish between rules. The rev shows the version of the rule, and indicates the updates made over time. The Reference is used by analysts to indicate the original source of information that inspired the creation of this rule in the first place.

## Rule Development: 

When it comes to actually creating Suricata rules, the 2 main strategies employed are signature-based detection, and anomaly-based detection. Signature-based detection focuses on the detection of specific elements within network traffic that are unique to the malware/attack we want to detect, which makes it highly effective when dealing with known threats as it can identify these threats with high precision, but makes it struggle to identify new threats where no signature exists yet. anomaly-based detection focuses on identifying specific behaviors that are characteristic to the malware/attack we want to detect, which gives it the advantage of being able to potentially identify new threats and zero-day attacks that a signature-based system could not. However, it does have higher rates of false positives due to the nature of it seeking outliers in network traffic.

A recent third approach to creating rules is stateful protocol analysis, or what I like to call “mindful” detection. This is effectively a variant of anomaly-based detection where we take advantage of a comprehensive understanding of the network being defended, track the state of network protocols, and compare the current observed behaviors to the expected state transitions of these protocols. Put simply, by keeping track of the state of each connection, we can identify deviations from expected behavior that might suggest malicious activity.

## Procedure:

When encountering a piece of malware you want to monitor the traffic for:

1. Determine the protocol that the malware will use for you to detect it (HTTP, TCP, etc.).
2. Determine the flow of traffic/ movement behavior we are looking to track. Are we looking for indications of incoming traffic? Are we looking for signs of malware that is already on a computer, and trying to reach externally out to a staging server? Are we expecting an exact IP, or looking at traffic going to a static IP on our network?
3. Determine what exact data we are looking for, and optimize the rule to cover it. Are we looking for an exact string in an HTTP cookie? Are we expecting a payload of a certain size? Are we anticipating a certain count of packets within a set amount of time? Is there any data that might cause a false flag that we want to ignore? The more specific we are with a rule, the more accurate and helpful it will be.
4. Open the custom rules file(most suricata setups will use the name “local.rules”), and create your rule, following the format discussed above.
5. Save the file, and then run Suricata to test and see if your rule is being loaded by running the command “suricata -c /etc/suricata/suricata.yaml -i wlan0”
6. Once your rule has been confirmed to work properly, test the rule by running Suricata on a packet capture file that captured the malware you are making the rule for, specifically by running “-r <path>”(you may need to run the malware in an isolated lab to gather a packet capture file to test). Does your rule detect the malware? If so, success! If not, review the captured activity of the malware, and tweak the rule as needed.
7. To ensure that the rule has been balanced properly, now run the rule against a packet capture file the contains normal traffic. If the rule does not trigger, than it is set properly. If it does trigger, review the logs to determine why it was triggered, and adjust it.

## Example: 

I want to create a rule to detect outbound activity from PowerShell Empire, a post-exploitation framework used by hackers.

- Judging by the file content in https://github.com/EmpireProject/Empire , This exploit will use the protocol http, so we will want to include that protocol in the rule
- This exploit will send http packets from our internal network to a server in the external network(with neither connection having a specified ip), so we will want to configure the rule to be $HOME_NET any -> $EXTERNAL_NET any
- This exploit causes the infected computer to reach out to an external server, which is identifiable in the http cookies, so we will specify this by including “flow:established,to_server:”
- When starting the exploit, it will send in the connection we are looking for a an http “GET” method, so we will monitor for this by adding “content:"GET"; http_method;”
- To focus the scope of our rule to http traffic, we will want to include the segment“content:"/"; http_uri; depth:1;”
- In the PowerShell Empire exploit(and most exploits in general) contains URIs that end with login/process.php, admin/get.php, and news.php, which is unusual for http traffic. We will search for this by adding to the rule the Perl Compatible Regular Expression “pcre:"/^(?:login\/process|admin\/get|news)\.php$/RU";”
- PowerShell Empire appears to include the string “session=” in the http data(which is unusual), so we will include this in the monitoring by adding “content:"session="; http_cookie;”
- PowerShell also includes Base64 in its http cookies, which is highly unusual. We will check for that by adding a Perl Compatible Regular Expression(pcre) to look for base64 encoded data: “pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi";”
- In the agent data for PowerShell Empire, it explicitly notes Mozilla/5.0 (Windows NT 6.1, which is uncommon in transfer data. We will include this in the rule by adding “content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1"; http_user_agent; http_start;”
- The HTTP headers that PowerShell Empire employs explicitly use ".php HTTP/1.1\r\nCookie: session=" in each connection. We can check for this by adding the rule content “content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session="; fast_pattern; http_header_names;”
- There are some common pieces of data in HTTP headers that are missing from the headers in PowerShell Empire, such as "Referer", "Cache", and "Accept". To reduce false positives, we will want to include these as negative content matches by adding “content:!"Referer"; content:!"Cache"; content:!"Accept";”.

Altogether this creates the following rule:

<pre>alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Possible PowerShell Empire Activity Outbound"; flow:established,to_server; content:"GET"; http_method; content:"/"; http_uri; depth:1; pcre:"/^(?:login\/process|admin\/get|news)\.php$/RU"; content:"session="; http_cookie; pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi"; content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1"; http_user_agent; http_start; content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session="; fast_pattern; http_header_names; content:!"Referer"; content:!"Cache"; content:!"Accept"; sid:2027512; rev:1;)</pre>

Now that I’ve made the rule, I want to test and see that it reacts to the PowerShell Empire exploit. I have captured some PowerShell Empire traffic in a pcap, and when I test it in Suricata’s offline mode, it successfully detects the exploit and stops running:

![image](https://github.com/user-attachments/assets/6f70251b-17d2-49fa-a264-0b7653327968)

![image](https://github.com/user-attachments/assets/0355250b-7abf-4c55-b116-78869d3500d7)

Lastly, to ensure that the rule will not create wildly false positives, I tested the rule on a pcap that contained general traffic data, and it does not flag anything in the packets captured:

![image](https://github.com/user-attachments/assets/28a2dd5e-8ed0-4c0a-97ce-7bb7a422c0ab)


