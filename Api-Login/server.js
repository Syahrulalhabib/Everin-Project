require('dotenv').config();
const Hapi = require('@hapi/hapi');
const firebaseAdmin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Initialize Firebase Admin
const serviceAccount = require(process.env.FIREBASE_CREDENTIALS_PATH);
firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccount),
});

const db = firebaseAdmin.firestore();

// Create HAPI server
const server = Hapi.server({
  port: 8080,
  host: '0.0.0.0',
  routes: {
    cors: true,
  },
});

// Register route
server.route({
  method: 'POST',
  path: '/register',
  handler: async (request, h) => {
    const { email, password, confirmPassword, fullname, height, weight, age, gender } = request.payload;

    // Validasi gender
    const validGenders = ['man', 'women'];
    if (!validGenders.includes(gender)) {
      return h.response({ message: 'Gender must be "man" or "women"' }).code(400);
    }

    // Cek apakah password dan confirmPassword sama
    if (password !== confirmPassword) {
      return h.response({ message: 'Passwords do not match' }).code(400);
    }

    // Enkripsi password
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4(); // Generate unique user ID

    // Simpan pengguna di Firestore
    try {
      const userRef = db.collection('users').doc(email);
      const userDoc = await userRef.get();

      if (userDoc.exists) {
        return h.response({ message: 'User already exists' }).code(400);
      }

      await userRef.set({
        userId, // Simpan userId
        email,
        fullname, // Simpan fullname
        password: hashedPassword,
        isLoggedIn: false, // User defaultnya belum login
        lastLogin: null, // Belum ada login
        height,
        weight,
        age,
        gender,
      });

      return h.response({ message: 'User registered successfully' }).code(201);
    } catch (error) {
      console.error(error);
      return h.response({ message: 'Failed to register user' }).code(500);
    }
  },
});

// Login route
server.route({
  method: 'POST',
  path: '/login',
  handler: async (request, h) => {
    const { email, password } = request.payload;

    try {
      const userRef = db.collection('users').doc(email);
      const userDoc = await userRef.get();

      if (!userDoc.exists) {
        return h.response({
          error: true,
          message: 'User not found',
        }).code(404);
      }

      const user = userDoc.data();

      // Verifikasi password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return h.response({
          error: true,
          message: 'Invalid Password',
        }).code(400);
      }

      // Generate JWT token
      const token = jwt.sign({ email, userId: user.userId }, process.env.JWT_SECRET, { expiresIn: '1h' });

      // Update Firestore: Set status isLoggedIn to true
      await userRef.update({
        isLoggedIn: true, // Tandai pengguna sedang login
        lastLogin: new Date(), // Set waktu login terakhir
      });

      // Kembalikan response dengan data user termasuk weight, height, age, gender
      return h.response({
        error: false,
        message: 'Login successful',
        loginResult: {
          userId: user.userId,    // userId dari Firestore
          name: user.fullname,    // fullname dari Firestore
          email: user.email,      // email dari Firestore
          height: user.height,    // height dari Firestore
          weight: user.weight,    // weight dari Firestore
          age: user.age,          // age dari Firestore
          gender: user.gender,    // gender dari Firestore
          token,                  // JWT token
        },
      }).code(200);

    } catch (error) {
      console.error(error);
      return h.response({
        error: true,
        message: 'Login failed',
      }).code(500);
    }
  },
});


// Logout route (menggunakan token untuk logout)
server.route({
  method: 'POST',
  path: '/logout',
  handler: async (request, h) => {
    const authHeader = request.headers['authorization'];

    if (!authHeader) {
      return h.response({ message: 'Authorization token required' }).code(400);
    }

    const token = authHeader.split(' ')[1]; // Ambil token dari header Authorization

    try {
      // Verifikasi token JWT
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const email = decoded.email;

      console.log('Decoded email from token:', email); // Log email yang terambil dari token

      // Periksa apakah dokumen pengguna ada di Firestore
      const userRef = db.collection('users').doc(email); // Gunakan email sebagai ID dokumen
      const userDoc = await userRef.get(); // Mengambil dokumen pengguna dari Firestore

      if (!userDoc.exists) {
        console.log('User not found in Firestore'); // Debugging log
        return h.response({ message: 'User not found' }).code(404);
      }

      // Jika dokumen ditemukan, update status login pengguna menjadi false
      await userRef.update({
        isLoggedIn: false, // Tandai pengguna sudah logout
        lastLogin: new Date(), // Update waktu logout terakhir
      });

      return h.response({ message: 'Logged out successfully' }).code(200);
    } catch (error) {
      console.error('Error:', error); // Tambahkan log error untuk memeriksa apa yang salah
      // Jika token tidak valid atau telah kadaluarsa
      return h.response({ message: 'Invalid or expired token' }).code(401);
    }
  },
});

// Initialize server
const init = async () => {
  await server.start();
  console.log('Server running on %s', server.info.uri);
};

init();
