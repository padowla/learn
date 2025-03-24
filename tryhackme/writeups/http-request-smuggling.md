# HTTP Request Smuggling

## Introduction

HTTP Request Smuggling is a vulnerability that arises when there are <mark style="color:red;">**mismatches in different web infrastructure components**</mark>. This includes proxies, load balancers, and servers that interpret the boundaries of HTTP requests. For example, consider a train station where tickets are checked at multiple points before boarding. If each checkpoint has different criteria for a valid ticket, a traveller could exploit these inconsistencies to board a train without a valid ticket. Similarly, in web requests, this vulnerability mainly involves the `Content-Length` and `Transfer-Encoding` **headers**, which indicate the end of a request body. When these headers are manipulated or interpreted inconsistently across components, it may result in one request being mixed with another.

<figure><img src="../../.gitbook/assets/image (449).png" alt=""><figcaption></figcaption></figure>

<mark style="color:orange;">**Request splitting**</mark> or <mark style="color:orange;">**HTTP desync**</mark> attacks are possible because of the nature of keep-alive connections and HTTP pipelining, which allow multiple requests to be sent over the same TCP connection.

When calculating the sizes for `Content-Length (CL`) and `Transfer-Encoding (TE)`, it's crucial to consider the presence of carriage return `\r` and newline `\n` characters. These characters are not only part of the HTTP protocol's formatting but also <mark style="color:yellow;">**impact the calculation of content sizes**</mark>.

Importance of Understanding HTTP Request Smuggling

1. Smuggled requests might <mark style="color:red;">**evade security mechanisms like Web Application Firewalls**</mark>. This potentially leads to unauthorized access or data leaks.
2. Attackers can <mark style="color:red;">**poison web caches**</mark> by smuggling malicious content, causing users to see incorrect or harmful data.
3. Smuggled requests can be <mark style="color:red;">**chained to exploit other vulnerabilities**</mark> in the system, amplifying the potential damage.

## Components of Modern Web Applications

* **Front-end server**: This is usually the reverse proxy or load balancer (Load balancing for web servers is often done by reverse proxies i.e: AWS Elastic Load Balancing, HAProxy, and F5 BIG-IP) that forwards the requests to the back-end. A reverse proxy sits before one or more web servers and forwards client requests to the appropriate web server. While they can also perform load balancing, their <mark style="color:orange;">**primary purpose is to provide a single access point and control for back-end servers**</mark>. Examples include NGINX, Apache with mod\_proxy, and Varnish.
* **Back-end server**: This server-side component processes user requests, interacts with databases, and serves data to the front-end. It's often developed using languages like PHP, Python, and Javascript and frameworks like Laravel, Django, or Node.js.
* **Databases**: Persistent storage systems where application data is stored. Examples of this are databases like MySQL, PostgreSQL, and NoSQL.
* **APIs (Application Programming Interfaces)**: Interfaces allow the front and back-end to communicate and integrate with other services.
* **Microservices**: Instead of a single monolithic back-end, many modern applications use microservices, which are small, independent services that communicate over a network, often using HTTP/REST or gRPC.

<figure><img src="../../.gitbook/assets/image (451).png" alt=""><figcaption></figcaption></figure>

## Role of Caching Mechanisms

<figure><img src="../../.gitbook/assets/image (452).png" alt=""><figcaption></figcaption></figure>

Caching is a technique used to store and reuse previously fetched data or computed results to speed up subsequent requests and computations. In the context of web infrastructure:

* **Content Caching**: By storing web content that doesn't change frequently (like images, CSS, and JS files), caching mechanisms can reduce the load on web servers and speed up content delivery to users.
* **Database Query Caching**: Databases can cache the results of frequent queries, reducing the time and resources needed to fetch the same data repeatedly.
* **Full-page Caching**: Entire web pages can be cached, so they don't need to be regenerated for each user. This is especially useful for websites with high traffic.
* **Edge Caching/CDNs**: Content Delivery Networks (CDNs) cache content closer to the users (at the "edge" of the network), reducing latency and speeding up access for users around the world.
* **API Caching**: Caching the responses can significantly reduce back-end processing for APIs that serve similar requests repeatedly.

## Understanding HTTP Request Structure

Every HTTP request comprises two main parts: the header and the body.

<figure><img src="../../.gitbook/assets/image (453).png" alt=""><figcaption></figcaption></figure>

1. <mark style="color:yellow;">**Request Line**</mark>: The first line of the request `POST /admin/login HTTP/1.1` is the request line. It consists of at least three items. First is the method, which in this case is "POST". The method is a one-word command that tells the server what to do with the resource. Second is the path component of the URL for the request. The path identifies the resource on the server, which in this case is "/admin/login". Lastly, the HTTP version number shows the HTTP specification to which the client has tried to make the message comply. Note that HTTP/2 and HTTP/1.1 have different structures.
2. <mark style="color:yellow;">**Request Headers**</mark>: This section contains metadata about the request, such as the type of content being sent, the desired response format, and authentication tokens. It's like the envelope of a letter, providing information about the sender, receiver, and the nature of the content inside.
3. <mark style="color:yellow;">**Message Body**</mark>: This is the actual content of the request. The body might be empty for a GET request, but for a POST request, it could contain form data, JSON payloads, or file uploads.

## Content-Length Header

The Content-Length header indicates the request or response body size in bytes. It informs the receiving server how much data to expect, ensuring the entire content is received.

<figure><img src="../../.gitbook/assets/image (454).png" alt=""><figcaption></figcaption></figure>

In this case the string included in body request `q=smuggledData` is long 14 chars.

## Transfer-Encoding Header

The Transfer-Encoding header specifies how the message body is formatted or encoded. One of the most common values for this header is **chunked**, which means the body is sent in multiple chunks, each with its size defined. Other directives of this header are **compress**, **deflate**, and **gzip**. For example:

<figure><img src="../../.gitbook/assets/image (455).png" alt=""><figcaption></figcaption></figure>

In chunked encoding, each chunk starts with the <mark style="color:yellow;">**number of bytes in that chunk**</mark> (**`in hexadecimal`**), followed by the actual data and a new line.

## How do HTTP request smuggling vulnerabilities arise?

HTTP Request Smuggling primarily occurs due to discrepancies in how different servers (like a front-end server and a back-end server) interpret HTTP request boundaries. For example:

1. If both Content-Length and Transfer-Encoding headers are present, ambiguities can arise.
2. Some components prioritize Content-Length, while others prioritize Transfer-Encoding.
3. <mark style="color:red;">**This discrepancy can lead to one component believing the request has ended while another thinks it's still ongoing, leading to smuggling.**</mark>

## Introduction to CL.TE Technique

{% hint style="warning" %}
Example: Suppose a front-end server uses the `Content-Length` header to determine the end of a request while a back-end server uses the `Transfer-Encoding` header. An attacker can craft a request that appears to have one boundary to the front-end server but a different boundary to the back-end server. This can lead to one request being "smuggled" inside another, causing unexpected behaviour and potential vulnerabilities.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (456).png" alt=""><figcaption></figcaption></figure>

<mark style="color:purple;">**CL.TE**</mark> stands for <mark style="color:purple;">**Content-Length/Transfer-Encoding**</mark>. The name CL.TE comes from the two headers involved: `Content-Length` and `Transfer-Encodin`g. In CL.TE technique, the attacker exploits discrepancies between how different servers (typically a front-end and a back-end server) prioritize these headers.

To exploit the CL.TE technique, an attacker crafts a request that includes both headers, ensuring that the front-end and back-end servers interpret the request boundaries differently. For example, an attacker sends a request like:

<figure><img src="../../.gitbook/assets/image (457).png" alt=""><figcaption></figcaption></figure>

Here, the <mark style="color:green;">front-end server</mark> sees the <mark style="color:green;">Content-Length of 80 bytes</mark> and believes the request ends after `isadmin=true`. However, the <mark style="color:orange;">back-end server</mark> sees the <mark style="color:orange;">Transfer-Encoding: chunked</mark> and interprets the 0 as the end of a chunk, <mark style="color:orange;">**making the second request the start of a new chunk**</mark>. This can lead to the back-end server treating the `POST /update HTTP/1.1` as a separate, new request, potentially giving the attacker unauthorized access.

### Incorrect Content-Length

When creating a request smuggling payload, if the `Content-Length` is not equal to the actual length of the content, several problems might arise.&#x20;

First, the server might process only the portion of the request body that matches the `Content-Length`. This could result in the smuggled part of the request being ignored or not processed as intended. For example, in the below screenshot, the original size of the body is 24 bytes.

<figure><img src="../../.gitbook/assets/image (458).png" alt=""><figcaption></figcaption></figure>

To verify that the `Content-Length` is valid, we can check the `/submissions` directory to verify if the whole body was saved in the .txt file:

<figure><img src="../../.gitbook/assets/image (459).png" alt=""><figcaption></figcaption></figure>

Since the size of the body `username=test&query=test` is 24 bytes, sending a `Content-Length` with a size lower than this will instruct the back-end server to interpret the request body differently. For example, if we set the `Content-Length` to 10 bytes while retaining the original content of the body, the back-end server will only process a part of that request body:

<figure><img src="../../.gitbook/assets/image (460).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (461).png" alt=""><figcaption></figcaption></figure>

## Introduction to TE.CL Technique

<mark style="color:purple;">**TE.CL**</mark> stands for <mark style="color:purple;">**Transfer-Encoding/Content-Length**</mark>. This technique is the opposite of the CL.TE method. In the TE.CL approach, the discrepancy in header interpretation is flipped because the front-end server uses the `Transfer-Encoding` header to determine the end of a request, and the back-end server uses the `Content-Length` header.

The TE.CL technique arises when the proxy prioritizes the `Transfer-Encoding` header while the back-end server prioritizes the `Content-Length` header.

<figure><img src="../../.gitbook/assets/image (462).png" alt=""><figcaption></figcaption></figure>

To exploit the TE.CL technique, an attacker crafts a specially designed request that includes both the `Transfer-Encoding` and `Content-Length` headers, aiming to create ambiguity in how the front-end and back-end servers interpret the request:

<figure><img src="../../.gitbook/assets/image (463).png" alt=""><figcaption></figcaption></figure>

In the above payload, the <mark style="color:green;">front-end server</mark> sees the <mark style="color:green;">Transfer-Encoding: chunked</mark> header and processes the request as chunked. The 4c (hexadecimal for 76) indicates that the next 76 bytes are part of the current request's body. The front-end server considers everything up to the 0 (indicating the end of the chunked message) as part of the body of the first request.

The <mark style="color:orange;">back-end server</mark>, however, uses the <mark style="color:orange;">Content-Length</mark> header, which is set to 4. It processes only the first 4 bytes of the request, not including the entire smuggled request `POST /update`. <mark style="color:orange;">**The remaining part of the request, starting from POST /update, is then interpreted by the back-end server as a separate, new request.**</mark>

The smuggled request is processed by the back-end server as if it were a legitimate, separate request. This request includes the `isadmin=true` parameter, which could potentially elevate the attacker's privileges or alter data on the server, depending on the application's functionality.

## Introduction to TE.TE Technique

<mark style="color:purple;">**Transfer Encoding Obfuscation**</mark>, also known as <mark style="color:purple;">**TE.TE**</mark> stands for <mark style="color:purple;">**Transfer-Encoding/Transfer-Encoding**</mark>. Unlike the CL.TE or TE.CL methods, the TE.TE technique arises when both the front-end and the back-end servers use the Transfer-Encoding header. In TE.TE technique, the attacker takes advantage of the servers inconsistent handling of Transfer-Encoding present in the HTTP headers.

The TE.TE vulnerability doesn't always require multiple Transfer-Encoding headers. Instead, it often involves a <mark style="color:yellow;">**single, malformed Transfer-Encoding header**</mark> that is interpreted differently by the front-end and back-end servers. In some cases, the front-end server might ignore or strip out the malformed part of the header and process the request normally, while the back-end server might interpret the request differently due to the malformed header, leading to request smuggling.

<figure><img src="../../.gitbook/assets/image (464).png" alt=""><figcaption></figcaption></figure>

To exploit the TE.TE technique, an attacker may craft a request that includes Transfer-Encoding headers that use different encodings. For example, an attacker sends a request like:

<figure><img src="../../.gitbook/assets/image (465).png" alt=""><figcaption></figcaption></figure>

In the above payload, the front-end server encounters two `Transfer-Encoding` headers. The first one is a standard chunked encoding, but the second one, `chunked1`, is non-standard. Depending on its configuration, the front-end server might process the request based on the first `Transfer-Encoding: chunked` header and ignore the malformed `chunked1`, interpreting the entire request up to the 0 as a single chunked message.

The back-end server, however, might handle the malformed `Transfer-Encoding: chunked1` differently. It could either reject the malformed part and process the request similarly to the front-end server or interpret the request differently due to the presence of the non-standard header. If it processes only the first 4 bytes as indicated by the `Content-length: 4`, the remaining part of the request starting from `POST /update` is then treated as a separate, new request.

The smuggled request with the `isadmin=true` parameter is processed by the back-end server as if it were a legitimate, separate request. This could lead to unauthorized actions or data modifications, depending on the server's functionality and the nature of the /update endpoint.
