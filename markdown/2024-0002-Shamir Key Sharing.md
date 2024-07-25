---
title: Implementing and Understanding Shamir Key Sharing
author: Joonkyo Kim (@rootwarp)
---
## DVT and Key sharing. What is it and why we need it

In the world of blockchain and cryptography, the concept of key sharing is crucial for maintaining network security and performance. One of the critical components in this field is the private key, which is used by validator clients to sign new blocks. This task is not only essential for the integrity and quality of the network but also directly related to the rewards validators receive.

To enhance security, it is a good practice to store only partial information of the private key on any single machine. This prevents the key from being easily compromised, as no single machine has the complete key. However, this introduces key sharing issues, such as how to distribute keys securely and maintain high uptime through threshold-based mechanisms.

One simple yet effective method for key sharing is [Shamir's Secret Sharing (SSS)](https://dl.acm.org/doi/10.1145/359168.359176). Let's delve into how this works by implementing simple codes

## Lagrange interpolation and Shamir Key Sharing

To understand Shamir's Secret Sharing, we need to grasp the basic concept of Lagrange interpolation.

In mathematics, if we have a linear function, we need at least two points to determine the formula. For a quadratic function, we need at least three points. Similarly, for a cubic function, we require four points. In general, for an n-degree polynomial, we need n+1 points to uniquely determine the polynomial. This principle is a key concept of Lagrange interpolation([ref](https://dl.acm.org/doi/10.1145/359168.359176)). 

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

[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) is secret sharing algorithm for distributing private information among a group and it relies on Lagrange interpolation to distribute and recover the secret. Here's how it works.

### Step 1: Set constants

Before splitting the secrets, two constants should be fixed, total number of shares and threshold to recover the secret.

Total number of shares means that how many partial secrets will be derived from the secrets. The symbol "N" will be used for convenience.

Threshold is the minimum number of shares to recover the secret from shared secrets. Likewise, it will be called as k.

In this example, let's assume, k = 3, N = 5.

### Step 2: Create random secret and polynomial

As described above, we assumed the threshold is 3 and that means we need at least 3 points on the unknown function to recover it. Hence, the unknown function should be quadratic function according to Lagrange interpolation theorem.
$$
f(x) = a_0 + a_1x + a_2x^2
$$
There are three coefficients, $a_0$, $a_1$ and $a_2$.
$a_0$ is the secret to be hidden. The specific integer can be used for it or random integer is also good.
Additionally, $a_1$ and $a_2$ are also set by random integers, then the entire polynomial discovered.

### Step 3: Generate secret shares

Creating secret shares is very simple. N, the number of shared secret had been chosen as 5 from the above. Then randomly create 5 numbers and those will be used for $x_0, x_1, x_2, x_3, x_4$. 
Next, find related $y$ values of each $x$ on the polynomial. Finally, 5 points on the polynomial has been derived.

### Step 4: Gather shares and recover the secret

From step 3, total 5 secret shares created but only 3 secret shares are required to recover the secret.
With Lagrange interpolation, the entire polynomial can be discovered by k points. Then, the secret can be calculated by set $x=0$ because of $f(0) = a_0$ ($a_0$ defined as secret from step 2).

## Implementation in Golang

Let's look at a simple implementation of Shamir's Secret Sharing in Golang.
Full source code is [here](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go)

### Step 1: Set constants

Same to the example above, let's set k = 3, N = 5.

```
    const (
        N = 5
        K = 3
    )
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L18-L21

Additionally, the modulo number has been chosen by Mersenne prime, $2^{127}$ as usual.

```
    p := new(big.Int).SetInt64(2)
    p.Exp(p, big.NewInt(127), nil)
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L23-L24

### Step 2: Create random secret and polynomial

The quadratic function has three coefficient and that means we should choose three random number to define a new polynomial. (One of coefficient will be secret!)

```
    secret, err := rand.Int(rand.Reader, p)
    assert.Nil(t, err)


    fmt.Println("New secret is", secret)

    coeffs := make([]*big.Int, K)
    coeffs[0] = secret


    // Create random polynomial
    for i := 1; i < K; i++ {
        coeffs[i], err = rand.Int(rand.Reader, p)
        //coeffs[i] = big.NewInt(int64(i))
        assert.Nil(t, err)
    }


    fmt.Println("created polynomial", coeffs)
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L29-L45

Now, we have a new secret and new polynomial.

### Step 3: Generate secret shares

To create secret shares, we should find some points on the polynomial which is defined above. In this example, it shows simply choose x values in serial for convenience. But random choosing also will work correctly.

```
    // Generate shares
    shares := make([]secretShare, N)
    for i := 0; i < N; i++ {
        x := new(big.Int).SetInt64(int64(i + 1))
        y := new(big.Int)


        y.Add(y, coeffs[0])
        for j := 1; j < K; j++ {
            tmp := new(big.Int).Exp(x, big.NewInt(int64(j)), nil)
            tmp.Mul(tmp, coeffs[j])
            y.Add(y, tmp)
        }
        newShare := secretShare{X: x, Y: y}
        shares[i] = newShare
    }
    //

    fmt.Println("=====")
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L47-L64

We have total 5 secret shares.
### Step 4: Gather shares and recover the secret

```
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


        lagN := new(big.Int).Div(numerator, denominator)
        lags[i] = lagN
    }
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L67-L84

```
    // Sigma
    secretRecovered := new(big.Int).SetInt64(0)
    for i := 0; i < K; i++ {
        secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y))
    }
```
- ref. https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L86-L90

## Problem and limitations

- Someone will get entire secret.
- Cannot prevent and verify malicious actor(?)

## Conclusion

SSS is using for many application. for example Vault.
hope this article would be useful to understand basics.

Next will be VSS(Verifiable Secret Sharing)
