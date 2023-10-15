/*token generate: 
  => open terminal and type: node
  => then type: require('crypto').randomBytes(64).toString('hex')
*/
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const app = express();
require("dotenv").config();

const port = process.env.PORT || 5000;

const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);

//middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }
  // bearer token
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

//mongoDB connection

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xm5hqxk.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const menuCollection = client.db("bistroDb").collection("menu");
    const reservationCollection = client
      .db("bistroDb")
      .collection("reservations");
    const reviewCollection = client.db("bistroDb").collection("reviews");
    const cartCollection = client.db("bistroDb").collection("carts");
    const usersCollection = client.db("bistroDb").collection("users");
    const paymentCollection = client.db("bistroDb").collection("payments");

    //jwt token generate
    app.post("/jwt", (req, res) => {
      const user = req.body;
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ accessToken });
    });

    //admin verify middleware
    //Warning: use verifyJWT middleware before using verifyAdmin middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }
      next();
    };

    /**
     * 0. dot not show secure link to those who should not see the link
     * 1. use jwt token: verifyJWT
     * 2. use verifyAdmin middleware
     */

    //users related apis
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find({}).toArray();
      res.send(result);
    });

    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (!email) {
        return res.send({ admin: false });
      }

      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res.send({ admin: false });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isAdmin = { admin: user.role === "admin" };
      res.send(isAdmin);
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      const existingUser = await usersCollection.findOne({
        email: user.email,
      });
      if (existingUser) {
        return res.send({ message: "User already exists" });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await usersCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    //menu related apis
    app.get("/menu", async (req, res) => {
      const result = await menuCollection.find({}).toArray();
      res.send(result);
    });

    app.get("/menu/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await menuCollection.findOne(query);
      res.send(result);
    });

    app.post("/menu", verifyJWT, verifyAdmin, async (req, res) => {
      const item = req.body;
      const insertResult = await menuCollection.insertOne(item);
      res.send(insertResult);
    });

    app.patch("/menu/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const query = { _id: new ObjectId(id) };
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          name: item.name,
          price: item.price,
          category: item.category,
          recipe: item.recipe,
          image: item.image,
        },
      };
      const result = await menuCollection.updateOne(query, updateDoc, options);
      res.send(result);
    });

    app.delete("/menu/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await menuCollection.deleteOne(query);
      res.send(result);
    });

    //reservation related apis
    app.get("/reservations", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.send([]);
      } else {
        const query = { email: email }; //query
        const result = await reservationCollection.find(query).toArray();
        res.send(result);
      }
    });

    app.get("/reservationpayment/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await reservationCollection.findOne(query);
      res.send(result);
    });

    app.get("/reservations/all", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await reservationCollection.find({}).toArray();
      res.send(result);
    });

    app.post("/reservations", verifyJWT, async (req, res) => {
      const reservation = req.body;
      const insertResult = await reservationCollection.insertOne(reservation);
      res.send(insertResult);
    });

    app.patch("/reservation/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const reservation = req.body;
      const query = { _id: new ObjectId(id) };
      const options = { upsert: true };
      if (reservation.hasOwnProperty("availability")) {
        const updateDoc = {
          $set: {
            availability: reservation.availability,
          },
        };
        const result = await reservationCollection.updateOne(
          query,
          updateDoc,
          options
        );
        res.send(result);
      } else if (reservation.hasOwnProperty("getService")) {
        const updateDoc = {
          $set: {
            getService: reservation.getService,
          },
        };
        const result = await reservationCollection.updateOne(
          query,
          updateDoc,
          options
        );
        res.send(result);
      }
    });

    app.delete("/reservation/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await reservationCollection.deleteOne(query);
      res.send(result);
    });

    //cart related apis
    app.get("/carts", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.send([]);
      }

      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }

      const query = { email: email }; //query
      const result = await cartCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/carts", async (req, res) => {
      const item = req.body;
      const existingItem = await cartCollection.findOne({
        foodId: item.foodId,
      });
      if (existingItem) {
        existingItem.quantity = existingItem.quantity + 1;

        // Update the existing item in the cart collection
        await cartCollection.updateOne(
          { _id: new ObjectId(existingItem._id) },
          { $set: { quantity: existingItem.quantity } }
        );
        res.send(existingItem);
      } else {
        item.quantity = 1;
        const insertResult = await cartCollection.insertOne(item);
        res.send(insertResult);
      }
    });

    app.delete("/carts/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await cartCollection.deleteOne(query);
      res.send(result);
    });

    app.patch("/carts/:id", async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const query = { _id: new ObjectId(id) };
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          quantity: item.quantity,
        },
      };
      const result = await cartCollection.updateOne(query, updateDoc, options);
      res.send(result);
    });

    //stripe payment
    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      const { price } = req.body;
      const amount = price * 100;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    //payment related apis

    app.get("/payments", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.send([]);
      }
      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }
      const query = { email: email }; //query
      const result = await paymentCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/payments", verifyJWT, async (req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment);

      //delete all items from cart
      const query = {
        _id: { $in: payment.menuItems.map((item) => new ObjectId(item.id)) },
      };
      const deleteResult = await cartCollection.deleteMany(query);

      res.send({ result: insertResult, deleteResult });
    });

    app.patch("/payments/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          orderStatus: "delivered",
        },
      };
      const result = await paymentCollection.updateOne(
        query,
        updateDoc,
        options
      );
      res.send(result);
    });

    app.get("/order-history", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.send([]);
      }
      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }
      const query = { email: email, categoryType: "Food Order" }; //query
      const result = await paymentCollection.find(query).toArray();
      res.send(result);
    });

    app.get("/orders/all", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await paymentCollection
        .find({ categoryType: "Food Order" })
        .toArray();
      res.send(result);
    });

    // reservation payment related apis
    app.post("/reservationpayments", verifyJWT, async (req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment);
      const query = { _id: new ObjectId(payment.orderId) };
      const updateDoc = {
        $set: {
          payment: "completed",
        },
      };
      const result = await reservationCollection.updateOne(query, updateDoc);
      res.send({ result: insertResult, updateResult: result });
    });

    //reviews related apis
    app.get("/reviews", async (req, res) => {
      const result = await reviewCollection
        .find({})
        .sort({ _id: -1 })
        .limit(5)
        .toArray();
      res.send(result);
    });

    app.post("/reviews", async (req, res) => {
      const review = req.body;
      const insertResult = await reviewCollection.insertOne(review);
      res.send(insertResult);
    });

    //admin stats related apis
    app.get("/admin-stats", verifyJWT, async (req, res) => {
      const users = await usersCollection.estimatedDocumentCount();
      const products = await menuCollection.estimatedDocumentCount();
      const orders = await paymentCollection.estimatedDocumentCount();

      //best way to get of a price field is to use group and sum operator

      const total = await paymentCollection
        .aggregate([
          {
            $group: {
              _id: null,
              total: {
                $sum: "$totalPrice",
              },
            },
          },
        ])
        .toArray();

      res.send({ users, products, orders, revenue: total[0].total });
    });

    //order stats related apis
    app.get("/order-stats", verifyJWT, async (req, res) => {
      // const payments = await paymentCollection.find({categoryType: "Food Order"}).toArray();

      const pipeline = [
        {
          $match: {
            categoryType: "Food Order",
          },
        },
        {
          $unwind: "$menuItems",
        },
        {
          $lookup: {
            from: "menu",
            let: { foodId: "$menuItems.foodId" }, // Define a variable for the foodId
            pipeline: [
              {
                $match: {
                  $expr: {
                    $eq: ["$_id", { $toObjectId: "$$foodId" }] // Compare as ObjectId
                  }
                }
              }
            ],
            as: "menuDetails"
          },
        },
        {
          $unwind: "$menuDetails",
        },
        {
          $group: {
            _id: "$menuDetails.category",
            itemCount: { $sum: "$menuItems.quantity" },
            totalPrice: {
              $sum: {
                $multiply: ["$menuItems.quantity", "$menuItems.price"],
              },
            },
          },
        },
        {
          $project: {
            _id: 0,
            category: "$_id",
            itemCount: 1,
            totalPrice: { $round: ["$totalPrice", 2] },
          },
        }
      ];
      

      const result = await paymentCollection.aggregate(pipeline).toArray();
      res.send(result);
    });


    /**
     * ------------------------------------
     * BANGLA SYSTEM(second best solution)
     * ------------------------------------
     * 1. load all payment(food order categoryType) from payment collection
     * 2. for each payment, get the items array
     * 3. for each item in the items array get the menu item from menu collection
     * 4. put them in an array: allOrderedItems
     * 5. separate the allOrderedItems by category using filter
     * 6. now get the quantity by using length and quantity: pizzas.length * pizzas.quantity
     * 7. for each category use reduce to get the total amount spent on that category
     */


    //user stats related apis

    app.get("/user-stats", verifyJWT, async (req, res) => {
      const email = req.query.email;
      const products = await menuCollection.estimatedDocumentCount();
      const pipeline = [
        {
          $group: {
            _id: "$category",
            count: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            category: "$_id",
          },
        },
      ];
      const result = await menuCollection.aggregate(pipeline).toArray();

      //based on user reviews, payments, orders, bookings count
      const totalReviews = (await reviewCollection.find({email: email}).toArray()).length;
      const totalPayments = (await paymentCollection.find({email: email}).toArray()).length;
      const totalOrders = (await paymentCollection.find({email: email, categoryType: "Food Order"}).toArray()).length;
      const totalBookings = (await reservationCollection.find({email: email}).toArray()).length;

      // console.log(totalReviews, totalPayments, totalBookings, totalOrders);

      res.send({ products, result, totalReviews, totalPayments, totalBookings, totalOrders });
    });
    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

//routes
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});

/**
 * ------------------------------------
 *          NAMING CONVENTION
 * ------------------------------------
 * users : userCollection
 * app.get('/users')
 * app.get('/users/:id')
 * app.post('/users')
 * app.patch('/users/:id')
 * app.delete('/users/:id')
 * **/
