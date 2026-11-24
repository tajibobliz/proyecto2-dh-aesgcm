"""Aritmetica modular basica.

Contiene las tres operaciones sobre las que se apoya todo el proyecto:

- exp_mod:            base^exponente mod modulo  (square-and-multiply)
- euclides_extendido: mcd(a, b) y los coeficientes de Bezout
- inverso_mod:        a^-1 mod m

Nota: Python no garantiza tiempo constante en operaciones con enteros
grandes, asi que esta implementacion es didactica y no resiste ataques
de canal lateral por tiempo. Se documenta como limitacion en el informe.
"""


def exp_mod(base: int, exponente: int, modulo: int) -> int:
    """Calcula (base ** exponente) % modulo con square-and-multiply.

    Idea: se recorre el exponente bit a bit, del menos significativo al
    mas significativo. En cada paso la base se eleva al cuadrado, y si el
    bit actual vale 1 se multiplica el resultado por la base.

    Ejemplo con exponente 13 = 1101 en binario:
        base^13 = base^8 * base^4 * base^1

    Costo: O(log exponente) multiplicaciones modulares, en lugar de las
    'exponente' multiplicaciones del metodo ingenuo. Como cada resultado
    se reduce modulo 'modulo', los numeros nunca crecen sin control.
    """
    if modulo <= 0:
        raise ValueError("El modulo debe ser positivo")
    if exponente < 0:
        raise ValueError("El exponente no puede ser negativo")
    if modulo == 1:
        return 0

    resultado = 1
    base %= modulo
    while exponente > 0:
        if exponente & 1:                      # bit actual en 1
            resultado = (resultado * base) % modulo
        base = (base * base) % modulo          # elevar al cuadrado
        exponente >>= 1                        # pasar al siguiente bit
    return resultado


def mcd(a: int, b: int) -> int:
    """Maximo comun divisor con el algoritmo de Euclides."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def euclides_extendido(a: int, b: int) -> tuple[int, int, int]:
    """Devuelve (g, x, y) tales que a*x + b*y = g = mcd(a, b).

    Es Euclides normal, pero llevando la cuenta de como se expresa cada
    resto como combinacion de a y b (identidad de Bezout).
    """
    r_ant, r = a, b
    x_ant, x = 1, 0
    y_ant, y = 0, 1
    while r != 0:
        cociente = r_ant // r
        r_ant, r = r, r_ant - cociente * r
        x_ant, x = x, x_ant - cociente * x
        y_ant, y = y, y_ant - cociente * y
    return r_ant, x_ant, y_ant


def inverso_mod(a: int, m: int) -> int:
    """Devuelve el inverso de a modulo m: el x tal que (a * x) % m == 1.

    Solo existe si mcd(a, m) == 1. Sale directo de Bezout:
    a*x + m*y = 1  =>  a*x = 1 (mod m).
    """
    if m <= 0:
        raise ValueError("El modulo debe ser positivo")
    g, x, _ = euclides_extendido(a % m, m)
    if g != 1:
        raise ValueError("No existe inverso: a y m no son coprimos")
    return x % m
