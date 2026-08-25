from Crypto.Hash import SHAKE256
import os
import json

class UOV:
    n = 60
    m = 24
    F = GF(256)
    Fxi = PolynomialRing(F, [f"x{i}" for i in range(n)])
    xi = list(Fxi._first_ngens(n))
    v = n - m

    def __init__(self):
        set_random_seed(int.from_bytes(os.urandom(32)))
        self.keygen()

    def bytes_to_vec(self, b):
        return vector(self.F, [self.F.from_integer(k) for k in b])

    def vec_to_bytes(self, vec):
        return bytes([k.to_integer() for k in vec])

    def generate_secret_system(self):
        self.secret_system = []
        for _ in range(self.m):
            curr_pol = self.F.random_element()
            for i in range(self.n):
                curr_pol += self.F.random_element() * self.xi[i]
                for j in range(max(self.v, i), self.n):
                    curr_pol += self.F.random_element() * self.xi[i] * self.xi[j]
            self.secret_system.append(curr_pol)

    def generate_secret_change_of_variable(self):
        cov_space = MatrixSpace(self.F, self.n, self.n)
        self.secret_cov = cov_space.random_element()
        while self.secret_cov.determinant() == 0:
            self.secret_cov = cov_space.random_element()

    def generate_public_key_from_secrets(self):
        new_variables = list(self.secret_cov * vector(self.Fxi, self.xi))
        self.public_system = []
        for secret_pol in self.secret_system:
            self.public_system.append(secret_pol(new_variables))

    def keygen(self):
        self.generate_secret_system()
        self.generate_secret_change_of_variable()
        self.generate_public_key_from_secrets()
        return self.secret_cov, self.public_system

    def sign(self, message):
        shake = SHAKE256.new()
        shake.update(message)
        # Target values
        hash_values = self.bytes_to_vec(shake.read(self.m))
        # Vinegar values
        v_values = list(self.bytes_to_vec(shake.read(self.v)))

        mat = []
        constant_vec = []
        # Fix vinegar values and deduce a linear system in the oil variables
        for secret_pol in self.secret_system:
            new_secret_pol = secret_pol(self.xi[:self.m] + v_values)
            mat.append([new_secret_pol.coefficient({self.xi[i]: 1}) for i in range(self.m)])
            constant_vec.append(new_secret_pol.constant_coefficient())
        mat = Matrix(self.F,mat)

        # Deterministic signature fails if the matrix is not invertible
        if not mat.is_invertible():
            return 0

        constant_vec = vector(self.F, constant_vec)
        # Constant part of the linear system
        output_vec = constant_vec + hash_values
        # Oil values can be deduced with linear system solving
        o_values = mat.inverse() * output_vec
        # Oil and vinegar values are aggregated
        ov_values = vector(self.F, list(o_values) + v_values)
        # They are transformed to the public coordinates
        x_values = self.secret_cov.inverse() * ov_values

        return self.vec_to_bytes(x_values)

    def verify(self, message, signature):
        try:
            shake = SHAKE256.new()
            shake.update(message)

            # Target values
            hash_values = self.bytes_to_vec(shake.read(self.m))
            # x-values contained in the signature
            x_values = self.bytes_to_vec(signature)

            # The x-values contained in the signature should solve the polynomial system
            # The target values correspond to the hash of the message
            a = True
            for public_pol, h in zip(self.public_system, hash_values):
                a = a & (public_pol(list(x_values)) == h)
            return a
        except:
            return 0

if __name__ == "__main__":

    Vinaigrette = UOV()

    data = {}
    while len(data) < 1600:
        message = os.urandom(16)
        signature = Vinaigrette.sign(message)
        if signature == 0:
            continue
        data[message.hex()] = signature.hex()
        assert(Vinaigrette.verify(message,signature))

    print(json.dumps(data, indent = 4))

    flag_signature = Vinaigrette.sign(b"Un mauvais vinaigre fait une mauvaise vinaigrette!")
    flag = f"FCSC{{{flag_signature.hex()}}}"
    with open("flag.txt", "w") as f:
        f.write(flag)
