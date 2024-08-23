+++ 
draft = false
date = 2024-08-16T13:46:11+09:00
title = "Lagrange Interpolation and Shamir's Secret Sharing"
description = "description"
slug = ""
authors = ["rootwarp"]
tags = ["crypto"]
categories = ["crypto"]
externalLink = ""
series = []
+++

## Key Sharing Mechanism

In the world of blockchain and cryptography, the concept of key sharing is crucial for maintaining network security and performance. One of the critical components in this field is the private key, which is used by validator clients to sign new blocks. This task is not only essential for the integrity and quality of the network but also directly related to the security of the network.

To enhance security, it is a good practice to store only partial information of the private key on any single machine. This prevents the key from being easily compromised, as no single machine has the complete key. However, this introduces key sharing issues, such as how to distribute keys securely and maintain high uptime through threshold-based mechanisms.

One simple yet effective method for key sharing is [Shamir's Secret Sharing (SSS)](https://dl.acm.org/doi/10.1145/359168.359176). In this article, simple description and code implementation of Shamir's Secret Sharing will be provided.

## Lagrange Interpolation and Shamir Key Sharing

It is essential to understand [Lagrange interpolation](https://dl.acm.org/doi/10.1145/359168.359176) to fully grasp the underlying process of Shamir's Secret Sharing.

In mathematics, at least two points are required to find exact formula of a linear function. For a quadratic function, at least three points are required. Similarly, for a cubic function, four points are required at least. In general, for an n-degree polynomial, n+1 points are required to determine the polynomial. This simple example is a key concept of Lagrange interpolation.

Assume that there is a quadratic function to be discovered and that means three points on the function are required to discover it.

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

Total number of shares means that how many partial secrets will be derived from the secrets. The symbol $N$ will be used for convenience.

Threshold is the minimum number of shares to recover the secret from shared secrets. Likewise, it will be called as k.

In this example, $k = 3, N = 5$ will be used for implementation.

### Step 2: Create random secret and polynomial

As described above, the value $3$ chosen for $k$ and that means at least 3 points are required to recover the unknown function. Hence, the unknown function should be quadratic according to Lagrange interpolation theorem like below.

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

Sample code implementation will be follow same steps of the description of SSS on the above.
In this article implemented code will be attached partially but the full source code can be found [here](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go)

### Step 1: Set constants

Same to the example above, let's set k = 3, N = 5.

```go
    const (
        N = 5
        K = 3
    )
```
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L18-L21) 

Additionally, the modulo number has been chosen by Mersenne prime, $2^{127}$ as usual.

```go
    p := new(big.Int).SetInt64(2)
    p.Exp(p, big.NewInt(127), nil)
```
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L23-L24)

### Step 2: Create random secret and polynomial

The quadratic function has three coefficient and that means we should choose three random number to define a new polynomial. (Keep in mind that $a_{0}$ is a secret)

```go
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
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L29-L45)

Now, we have a new secret and a new polynomial.

### Step 3: Generate secret shares

To create secret shares, we should find some points on the polynomial which is defined above. In the example on below, it shows that x values are chosen in serial for convenience but random choose also works correctly.

```go
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
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L47-L64)

Then, total five shared secrets are created.

### Step 4: Gather shared secrets and recover the secret

From Step 3, total 5 shared secrets are created. In this section, the recovering process will be implemented by using shared secrets which created step 3.

To recover the secret,  at least $k(=3)$ number of shared secrets are required as decided step 1. Even if implemented example has all of shared secrets, only $k(=3)$ shared secrets are used to verify the mechanism is working.

If $k(=3)$ shared secrets are collected, Lagrange basis should be calculated for the next step.

As described above, Lagrange basis can be calculated like below,

$$\ell_0(x) = \frac{x - x_1}{x_0 - x_1} \cdot \frac{x - x_2}{x_0 - x_2}$$

But now, this step is for recovering the secret and that it can be derived by put $x=0$. So, calculated constant which the implemented code is calculating for seems like below.

$$\ell_0(0) = \frac{x_1 x_2}{(x_0 - x_1)(x_0 - x_2)}$$

For sure, $x_{0}, x_{1} x_{2}$  are x values of shared secrets created at step 3.

```go
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
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L67-L84)

If Lagrange basis are calculated, the secret can be recovered by multiply $y$ to each basis and cumulating all of them.

```go
    // Sigma
    secretRecovered := new(big.Int).SetInt64(0)
    for i := 0; i < K; i++ {
        secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y))
    }
```
- [code link](https://github.com/rootwarp/snippets/blob/fc4dce4d97057e4d014a58c23e1782da27844001/golang/ethereum/dvt/shamir_test.go#L86-L90)

Now, the secret is recovered on `secretRecovered`.

## Problem and limitations

Shamir's Secret Sharing is very simple to understand and implement but still it is powerful. But there are some drawbacks.

First, Shamir's Secret Sharing cannot prevent malicious nodes. In general, shared secrets will be distributed into multiple nodes(or machine) and a single node will have only a single shared secret. But if one of the node who have shared secret send invalid shared secret intentionally, the secret cannot be recovered.

Seconds, a single node should have the secret to split it into shared secrets. Additionally, any node can reveal the secret if it has enough number of shared secret. So, every node who have shared secret should be authorized entity to keep secret.

## Conclusion

Incorporating key sharing methods like Shamir's Secret Sharing significantly improves the security and robustness of blockchain networks. By dividing the private key into multiple shares across different nodes, these techniques reduce the risk of key compromise, which is a major concern in cryptographic systems. Moreover, it eliminates the risk of a single point of failure since multiple shares are needed to reconstruct the private key.

However, Shamir's Secret Sharing has some drawbacks when it comes to distribute shared secrets publicly. The private key cannot be recovered if the adversary in the group maliciously shares invalid shared secret. Moreover, the adversary could potentially recovers the private key if they can manage to obtain a number of secret shares exceeding the threshold.

Despite these limitations, Shamir's Secret Sharing remains very powerful when the node holding the shared secret are trustworthy. For instance, [Hashcorp Vault](https://developer.hashicorp.com/vault/docs/concepts/seal) utilizes Shamir's Secret Sharing to divide its master key and distributes the shares among operators.
