# jscalc

In the mysterious depths of the digital sea, a specialized JavaScript calculator has been crafted by tech-savvy squids. With multiple arms and complex problem-solving skills, these cephalopod engineers use it for everything from inkjet trajectory calculations to deep-sea math. Attempt to outsmart it at your own risk! 🦑

<figure><img src="../../.gitbook/assets/image (434).png" alt=""><figcaption></figcaption></figure>

If we analyze the request made by browser to the backend we see an endpoint called:

<figure><img src="../../.gitbook/assets/image (435).png" alt=""><figcaption></figcaption></figure>

The result is passed by backend to frontend using JSON object.

The HTTP Header X-Powered-By tells us that we're speaking with Node.js.

The global object process can be used to gain more information on the current Node.js process. As it is global it is not necessary to use require(). It provides many useful properties and methods to get better control over system interactions.

`process.cwd()` for example returns the current working directory of the Node.js process.

<figure><img src="../../.gitbook/assets/image (436).png" alt=""><figcaption></figcaption></figure>

`readdir()`

Just as the dir command in MS Windows or the ls command on Linux, it is possible to use the method `readdir` or `readdirSync` of the fs class to list the content of the directory . The difference between these both functions is that the latter is the synchronous version.

The ‘.’ points to the current directory. The ‘..’ reads the previous directory.

<figure><img src="../../.gitbook/assets/image (437).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (438).png" alt=""><figcaption></figcaption></figure>

`readFile()`

Once the file names are obtained, the attacker can use other commands to view the content of the data. The methods `readFile` or `readFileSync` provide the option to read the entire content of a file. Again the latter is the synchronous version. As argument just pass the path to the file for the synchronous version.

Retrieve the flag:

<figure><img src="../../.gitbook/assets/image (439).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (440).png" alt=""><figcaption></figcaption></figure>
