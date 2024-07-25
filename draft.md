

# DVT and Key Sharing: What It Is and Why We Need It

%% Review required %%

In the world of blockchain and cryptography, the concept of key sharing is crucial for maintaining network security and performance. One of the critical components in this field is the private key, which is used by validator clients to sign new blocks. This task is not only essential for the integrity and quality of the network but also directly related to the rewards validators receive.

To enhance security, it is a good practice to store only partial information of the private key on any single machine. This prevents the key from being easily compromised, as no single machine has the complete key. However, this introduces key sharing issues, such as how to distribute keys securely and maintain high uptime through threshold-based mechanisms.

One simple yet effective method for key sharing is Shamir's Secret Sharing (SSS). Let's delve into how this works and the mathematics behind it.

## Lagrange Interpolation

To understand Shamir's Secret Sharing, we need to grasp the basic concept of Lagrange interpolation.

In mathematics, if we have a linear function, we need at least two points to determine the formula. For a quadratic function, we need at least three points. Similarly, for a cubic function, we require four points. In general, for an n-degree polynomial, we need n+1 points to uniquely determine the polynomial. This principle is a key concept of Lagrange interpolation.

Let's assume there is a quadratic function which we want to discover, then we should have three points on the function.
According to the theory, Lagrange basis polynomials should be calculated like below.
$$\ell_0(x) = \frac{x - x_1}{x_0 - x_1} \cdot \frac{x - x_2}{x_0 - x_2}$$
$$\ell_1(x) = \frac{x - x_0}{x_1 - x_0} \cdot \frac{x - x_2}{x_1 - x_2}$$
$$\ell_2(x) = \frac{x - x_0}{x_2 - x_0} \cdot \frac{x - x_1}{x_2 - x_1}$$

Then, the unknown function can be discovered by linear combination.
$$
f(x) = \sum_{j=0}^{2} y_j \cdot \ell_j(x) = y_0 \ell_0(x) + y_1 \ell_1(x) + y_2 \ell_2(x)
$$

## Shamir's Secret Sharing
Shamir's Secret Sharing is secret sharing algorithm for distributing private information among a group[https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing] and it relies on Lagrange interpolation to distribute and recover the secret. Here's how it works.

### Step 1: Set constants
Before splitting the secrets, two constants should be fixed, total number of shares and threshold to recover the secret.

Total number of shares means that how many partial secrets will be derived from the secrets. The symbol "N" will be used for convenience.

Threshold is the minimum number of shares to recover the secret from shared secrets. Likewise, it will be called as k.

In this example, let's assume, k = 3, N = 5.
### Step 2: Create random secret and polynomial
As described above, we can discover quadratic function by three points.

$$
f(x) = a_0 + a_1x + a_2x^2
$$
There are three coefficients, $a_0$, $a_1$ and $a_2$.
$a_0$ is the secret to be hidden. The specific integer can be used for it or random integer is also good.
Additionally, $a_1$ and $a_2$ are also set by random integers, then the entire polynomial discovered.
### Step 3: Generate secret shares
Creating secret shares is very simple. N, the number of shared secret had been chosen as 5 from the above. Then randomly create 5 numbers and those will be used for $x_0, x_1, x_2, x_3, x_4$.
Next, find related $y$ values of each $x$ on the polynomial.
Finally, 5 points on the polynomial has been derived.
### Step 4: Gather shares and recover the secret
From step 3, total 5 secret shares created but only 3 secret shares are required to recover the secret.
With Lagrange interpolation, the entire polynomial can be discovered by k points. Then, the secret can be calculated by set $x=0$ because of $f(0) = a_0$ ($a_0$ defined as secret from step 2).
## Implementation in Golang

Let's look at a simple implementation of Shamir's Secret Sharing in Golang.

### Preparation
choose below parameters
1. N: total number of shared secrets
2. k: threshold to recover the secret
3. Modulus: in here, usual Merssene prime 127 used.

### Sharing Secret

1. **Choose a random secret**: Simple random
2. **Randomly create a polynomial**
	1. secret will be constant
	2. remain coeffients are chosen randomly.
	3. then, final polyonmial created.
3. **Retrieve points (shares).**
	1. randomly choose x
	2. and find derived y.
	3. (x, y) is a shared secret.
### Recovering Secret

1. **Gather points and ensure the number is greater than or equal to the threshold.**
2. **Calculate Lagrange interpolation to recover the secret.**

Here’s a Golang code example to illustrate this process:

```golang
func TestShamirSecretSharing(t *testing.T) {
    const (
        N = 5 // Number of shares
        K = 3 // Threshold
    )

    p := new(big.Int).SetInt64(2)
    p.Exp(p, big.NewInt(127), nil)
    p.Sub(p, big.NewInt(1))

    secret, err := rand.Int(rand.Reader, p)
    assert.Nil(t, err)

    // Random polynomial
    coeffs := make([]*big.Int, K)
    coeffs[0] = secret

    for i := 1; i < K; i++ {
        coeffs[i], err = rand.Int(rand.Reader, p)
        assert.Nil(t, err)
    }

    polynomial := NewPolynomial(coeffs, p)

    // Create partial secrets
    shares := make([]secretShare, N)
    for i := 0; i < N; i++ {
        x, err := rand.Int(rand.Reader, p)
        assert.Nil(t, err)

        y := polynomial.Eval(x)

        newShare := secretShare{X: x, Y: y}
        fmt.Println("share", newShare)
        shares[i] = newShare
    }

    // Recover secret using Lagrange interpolation
    lags := make([]*big.Int, K)
    for i := 0; i < K; i++ {
        curX := shares[i].X

        numerator := new(big.Int).SetInt64(1)
        denominator := new(big.Int).SetInt64(1)
        for j := 0; j < K; j++ {
            if i == j {
                continue
            }

            numerator.Mul(numerator, new(big.Int).Sub(big.NewInt(0), shares[j].X))
            denominator.Mul(denominator, new(big.Int).Sub(curX, shares[j].X))
        }

        lagN := new(big.Int)
        lagN.ModInverse(denominator, p)
        lagN.Mul(lagN, numerator)

        lags[i] = lagN
    }

    // Sigma
    secretRecovered := new(big.Int).SetInt64(0)
    for i := 0; i < K; i++ {
        secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y)).Mod(secretRecovered, p)
    }

    fmt.Println("Original secret is", secret.String())
    fmt.Println("Recovered secret is", secretRecovered.String())

    assert.Equal(t, secret.String(), secretRecovered.String())
}
```

## Problems and Limitations

While Shamir's Secret Sharing is a powerful technique, it has some limitations:

- **Complete Secret Exposure**: If an attacker gathers enough shares (meeting the threshold), they can reconstruct the entire secret.
- **Malicious Actors**: The method doesn’t inherently prevent or verify the presence of malicious actors who might provide false shares.

## Conclusion

Shamir's Secret Sharing is widely used in various applications to secure sensitive information. One notable example is its implementation in Vault, a tool for securely managing secrets.

This article has provided a basic understanding of Shamir's Secret Sharing and its implementation. In future articles, we will explore more advanced topics such as Verifiable Secret Sharing (VSS).

We hope this article helps you grasp the essentials of key sharing and its importance in maintaining security and reliability in cryptographic systems.
