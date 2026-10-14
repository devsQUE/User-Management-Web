/* =========================================
   TVS CREDIT USER MANAGER
   SECURE BACKEND
========================================= */

const express = require("express");
const path = require("path");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

require("dotenv").config();

/* =========================================
   CONFIGURATION
========================================= */

const app = express();

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// --------------------------------------------
// Extension Login Session Tracking
// --------------------------------------------

const activeUserSessions = new Map();

const SESSION_TIMEOUT_MS = 60 * 1000; // 60 seconds

function getLoginStatus(userId) {
  const session = activeUserSessions.get(userId);

  if (!session) {
    return "logged_out";
  }

  const lastSeen = Number(session.lastSeenAt || 0);

  if (!lastSeen || Date.now() - lastSeen > SESSION_TIMEOUT_MS) {
    activeUserSessions.delete(userId);
    return "logged_out";
  }

  return "active";
}

/* =========================================
   VALIDATE ENVIRONMENT
========================================= */

if (!SUPABASE_URL) {
  console.error("Missing SUPABASE_URL in .env");

  process.exit(1);
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_SERVICE_ROLE_KEY in .env");

  process.exit(1);
}

if (!ADMIN_EMAIL) {
  console.error("Missing ADMIN_EMAIL in .env");

  process.exit(1);
}

/* =========================================
   SUPABASE ADMIN CLIENT
========================================= */

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

/* =========================================
   MIDDLEWARE
========================================= */

app.use(cors());

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true,
  }),
);

/* =========================================
   STATIC FRONTEND
========================================= */

app.use(express.static(path.join(__dirname, "public")));

/* =========================================
   HEALTH CHECK
========================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "TVS Credit User Manager API is running.",
  });
});

/* =========================================
   AUTHENTICATE ADMIN
========================================= */

async function authenticateAdmin(req) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    throw new Error("Authentication required.");
  }

  if (!authorization.toLowerCase().startsWith("bearer ")) {
    throw new Error("Invalid authorization header.");
  }

  const accessToken = authorization.slice(7).trim();

  if (!accessToken) {
    throw new Error("Missing access token.");
  }

  /*
    Use the user's access token to
    identify the logged-in Supabase user.
  */

  const { data, error } = await supabaseAdmin.auth.getUser(accessToken);

  if (error || !data?.user) {
    throw new Error("Invalid or expired session.");
  }

  const user = data.user;

  /*
    Only the configured admin account
    can access this management API.
  */

  if (user.email?.toLowerCase() !== ADMIN_EMAIL.toLowerCase()) {
    throw new Error("Administrator access required.");
  }

  return user;
}

// --------------------------------------------
// Authenticate Extension User
// --------------------------------------------

async function authenticateExtensionUser(req) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    throw new Error("Authentication required.");
  }

  if (!authorization.toLowerCase().startsWith("bearer ")) {
    throw new Error("Invalid authorization header.");
  }

  const accessToken = authorization.slice(7).trim();

  if (!accessToken) {
    throw new Error("Missing access token.");
  }

  const { data, error } = await supabaseAdmin.auth.getUser(accessToken);

  if (error || !data?.user) {
    throw new Error("Invalid or expired session.");
  }

  return data.user;
}

/* =========================================
   EXTENSION USER LOGIN
========================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (!userId?.trim()) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Password is required.",
      });
    }

    const loginId = userId.trim().toLowerCase();

    /*
      Find the user by the User ID stored
      in Supabase user metadata.
    */
    const { data, error } =
      await supabaseAdmin.auth.admin.listUsers({
        page: 1,
        perPage: 1000,
      });

    if (error) {
      throw error;
    }

    const targetUser = (data?.users || []).find((user) => {
      const metadata = user.user_metadata || {};

      return (
        metadata.userId?.trim().toLowerCase() === loginId
      );
    });

    if (!targetUser) {
      return res.status(401).json({
        success: false,
        message: "Invalid User ID or password.",
      });
    }

    /*
      Never allow a disabled account to log in.
    */
    if (isUserDisabled(targetUser)) {
      return res.status(403).json({
        success: false,
        message: "This account is disabled.",
      });
    }

    if (!targetUser.email) {
      return res.status(401).json({
        success: false,
        message: "User account email is missing.",
      });
    }

    /*
      Authenticate the actual Supabase account
      using the user's email and password.
    */
    const response = await fetch(
      `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          apikey: process.env.SUPABASE_PUBLISHABLE_KEY,
        },

        body: JSON.stringify({
          email: targetUser.email,
          password,
        }),
      }
    );

    const session = await response.json();

    if (!response.ok || !session?.access_token) {
      return res.status(401).json({
        success: false,
        message:
          session?.error_description ||
          "Invalid User ID or password.",
      });
    }

    const metadata = targetUser.user_metadata || {};

    const sessionVersion = Number(
      metadata.sessionVersion || 1
    );

    /*
      Mark this user as actively logged in.
    */
    activeUserSessions.set(targetUser.id, {
      lastSeenAt: Date.now(),
      sessionVersion,
    });

    return res.json({
      success: true,

      session: {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
        expires_at: session.expires_at,
        user: session.user,
      },

      user: {
        id: targetUser.id,
        userId: metadata.userId || "",
        name: metadata.name || "",
        email: targetUser.email,
      },

      sessionVersion,
    });

  } catch (error) {
    console.error(
      "[POST /api/auth/login]",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Unable to log in.",
    });
  }
});

/* =========================================
   AUTH MIDDLEWARE
========================================= */

async function requireAdmin(req, res, next) {
  try {
    const admin = await authenticateAdmin(req);

    req.admin = admin;

    next();
  } catch (error) {
    console.error("[Auth]", error.message);

    return res.status(401).json({
      success: false,
      message: error.message || "Authentication failed.",
    });
  }
}

/* =========================================
   EXTENSION SESSION HEARTBEAT
========================================= */

app.post("/api/session/heartbeat", async (req, res) => {
  try {
    const user = await authenticateExtensionUser(req);

    /*
      Verify that the user still exists.
    */
    const { data, error } =
      await supabaseAdmin.auth.admin.getUserById(user.id);

    if (error || !data?.user) {
      activeUserSessions.delete(user.id);

      return res.status(401).json({
        success: false,
        message: "User account no longer exists.",
      });
    }

    const targetUser = data.user;

    /*
      Disabled users must not remain logged in.
    */
    if (isUserDisabled(targetUser)) {
      activeUserSessions.delete(user.id);

      return res.status(403).json({
        success: false,
        message: "Your account has been disabled.",
      });
    }

    /*
      Read the current session version.
      Admin force logout increments this value.
    */
    const metadata = targetUser.user_metadata || {};

    const sessionVersion =
      Number(metadata.sessionVersion || 1);

    /*
      Update the active session timestamp.
    */
    activeUserSessions.set(user.id, {
      lastSeenAt: Date.now(),
      sessionVersion,
    });

    return res.json({
      success: true,
      loginStatus: "active",
      sessionVersion,
    });

  } catch (error) {
    console.error(
      "[POST /api/session/heartbeat]",
      error
    );

    return res.status(401).json({
      success: false,
      message:
        error.message ||
        "Session validation failed.",
    });
  }
});

/* =========================================
   EXTENSION SESSION LOGOUT
========================================= */

app.post(
  "/api/session/logout",
  async (req, res) => {

    try {

      const user =
        await authenticateExtensionUser(req);

      activeUserSessions.delete(user.id);

      return res.json({
        success: true,
        loginStatus: "logged_out"
      });

    } catch (error) {

      console.error(
        "[POST /api/session/logout]",
        error
      );

      return res.status(401).json({
        success: false,
        message:
          error.message ||
          "Logout failed."
      });

    }

  }
);

/* =========================================
   GET USERS
========================================= */

app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({
      page: 1,
      perPage: 1000,
    });

    if (error) {
      throw error;
    }

    const users = (data?.users || [])
      .filter((user) => {
        /*
              Don't display the admin account
              in the normal user-management
              list.
            */

        return user.email?.toLowerCase() !== ADMIN_EMAIL.toLowerCase();
      })
      .map((user) => {
        const metadata = user.user_metadata || {};

        const disabled = isUserDisabled(user);

        return {
          id: user.id,

          name: metadata.name || "",

          email: user.email || "",

          userId: metadata.userId || "",

          status: disabled ? "disabled" : "active",

          createdAt: user.created_at,

          lastSignInAt: user.last_sign_in_at || null,

          loginStatus: getLoginStatus(user.id),
        };
      });

    return res.json({
      success: true,
      users,
    });
  } catch (error) {
    console.error("[GET /api/users]", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load users.",
    });
  }
});

/* =========================================
   CREATE USER
========================================= */

app.post("/api/users", requireAdmin, async (req, res) => {
  try {
    const { name, email, userId, password, status } = req.body;

    /*
        Validate required fields.
      */

    if (!name?.trim()) {
      return res.status(400).json({
        success: false,
        message: "User name is required.",
      });
    }

    if (!email?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email is required.",
      });
    }

    if (!userId?.trim()) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Password is required.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters.",
      });
    }

    /*
        Create the Supabase Auth user.
      */

    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email: email.trim(),

      password,

      email_confirm: true,

      user_metadata: {

  name:
    name.trim(),

  userId:
    userId.trim(),

  sessionVersion:
    1

},
    });

    if (error) {
      throw error;
    }

    const createdUser = data?.user;

    /*
        If the new account should start
        disabled, disable it immediately.
      */

    if (createdUser && status === "disabled") {
      const { error: disableError } =
        await supabaseAdmin.auth.admin.updateUserById(createdUser.id, {
          ban_duration: "876000h",
        });

      if (disableError) {
        console.error(
          "[Create User] Unable to disable new user:",
          disableError,
        );
      }
    }

    return res.json({
      success: true,

      user: {
        id: createdUser?.id,

        name: name.trim(),

        email: email.trim(),

        userId: userId.trim(),

        status: status === "disabled" ? "disabled" : "active",

        createdAt: createdUser?.created_at,
      },
    });
  } catch (error) {
    console.error("[POST /api/users]", error);

    return res.status(400).json({
      success: false,
      message: getSupabaseErrorMessage(error),
    });
  }
});

/* =========================================
   UPDATE USER
========================================= */

app.patch("/api/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const { name, email, userId: loginId, password, status } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is missing.",
      });
    }

    const updates = {};

    /*
        Update email.
      */

    if (typeof email === "string" && email.trim()) {
      updates.email = email.trim();

      /*
          Automatically confirm the
          updated email.
        */

      updates.email_confirm = true;
    }

    /*
        Update password.
      */

    if (typeof password === "string" && password.length > 0) {
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must be at least 6 characters.",
        });
      }

      updates.password = password;
    }

    /*
        Update user metadata.
      */

const {
  data: existingUserData,
  error: existingUserError
} =
  await supabaseAdmin.auth.admin
    .getUserById(userId);

if (existingUserError) {
  throw existingUserError;
}

const existingMetadata =
  existingUserData?.user?.user_metadata || {};

updates.user_metadata = {

  ...existingMetadata,

  name:
    typeof name === "string"
      ? name.trim()
      : "",

  userId:
    typeof loginId === "string"
      ? loginId.trim()
      : ""

};

    /*
        Enable / disable account.
      */

    if (status === "disabled") {
      updates.ban_duration = "876000h";
    } else {
      updates.ban_duration = "none";
    }

    const { data, error } = await supabaseAdmin.auth.admin.updateUserById(
      userId,
      updates,
    );

    if (error) {
      throw error;
    }

    const updatedUser = data?.user;

    return res.json({
      success: true,

      user: {
        id: updatedUser?.id,

        name: updatedUser?.user_metadata?.name || "",

        email: updatedUser?.email || "",

        userId: updatedUser?.user_metadata?.userId || "",

        status: status === "disabled" ? "disabled" : "active",

        createdAt: updatedUser?.created_at,
      },
    });
  } catch (error) {
    console.error("[PATCH /api/users/:id]", error);

    return res.status(400).json({
      success: false,
      message: getSupabaseErrorMessage(error),
    });
  }
});

/* =========================================
   FORCE LOGOUT USER
========================================= */

app.post("/api/users/:id/logout", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is missing.",
      });
    }

    /*
        Get the target user.
      */

    const { data, error } = await supabaseAdmin.auth.admin.getUserById(userId);

    if (error) {
      throw error;
    }

    const targetUser = data?.user;

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    /*
        Never allow the administrator
        account to be force logged out
        through the user manager.
      */

    if (targetUser.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: "The administrator account cannot be logged out here.",
      });
    }

    /*
        Increase the session version.

        The extension will later compare
        this value with the version stored
        during login.
      */

    const metadata = targetUser.user_metadata || {};

    const currentVersion = Number(metadata.sessionVersion || 1);

    const nextVersion = currentVersion + 1;

    const { error: updateError } =
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        user_metadata: {
          ...metadata,
          sessionVersion: nextVersion,
          forceLogoutAt: new Date().toISOString(),
        },
      });

   if (updateError) {
  throw updateError;
}

// Immediately mark the user as logged out.
activeUserSessions.delete(targetUser.id);

return res.json({
      success: true,
      message: "User has been logged out successfully.",
      sessionVersion: nextVersion,
    });
  } catch (error) {
    console.error("[POST /api/users/:id/logout]", error);

    return res.status(400).json({
      success: false,
      message: getSupabaseErrorMessage(error),
    });
  }
});

/* =========================================
   DELETE USER
========================================= */

app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is missing.",
      });
    }

    /*
        Never allow this endpoint to
        delete the configured admin.
      */

    const { data, error } = await supabaseAdmin.auth.admin.getUserById(userId);

    if (error) {
      throw error;
    }

    const targetUser = data?.user;

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    if (targetUser.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: "The administrator account cannot be deleted.",
      });
    }

    const { error: deleteError } =
      await supabaseAdmin.auth.admin.deleteUser(userId);

    if (deleteError) {
      throw deleteError;
    }

    // Immediately remove the deleted user's active session.
activeUserSessions.delete(userId);

    return res.json({
      success: true,
      message: "User deleted successfully.",
    });
  } catch (error) {
    console.error("[DELETE /api/users/:id]", error);

    return res.status(400).json({
      success: false,
      message: getSupabaseErrorMessage(error),
    });
  }
});

/* =========================================
   USER STATUS CHECK
========================================= */

function isUserDisabled(user) {
  if (!user) {
    return false;
  }

  /*
    Supabase can expose a banned-until
    timestamp for banned users.
  */

  if (!user.banned_until) {
    return false;
  }

  const bannedUntil = new Date(user.banned_until).getTime();

  if (Number.isNaN(bannedUntil)) {
    return false;
  }

  return bannedUntil > Date.now();
}

/* =========================================
   SUPABASE ERROR HANDLING
========================================= */

function getSupabaseErrorMessage(error) {
  if (!error) {
    return "An unexpected error occurred.";
  }

  if (error.message) {
    return error.message;
  }

  return "An unexpected error occurred.";
}

/* =========================================
   FRONTEND FALLBACK
========================================= */

app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ========================================
// SERVER SELF-HEARTBEAT
// ========================================

const SELF_URL = process.env.RENDER_EXTERNAL_URL;

if (SELF_URL) {
  setInterval(async () => {
    try {
      const response = await fetch(`${SELF_URL}/api/health`);

      console.log(
        "[Heartbeat] Server status:",
        response.status
      );
    } catch (error) {
      console.error(
        "[Heartbeat] Request failed:",
        error.message
      );
    }
  }, 5 * 60 * 1000);
}

/* =========================================
   START SERVER
========================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log("====================================");
  console.log("TVS Credit User Manager");
  console.log(`Server running on port ${PORT}`);
  console.log(`Admin: ${ADMIN_EMAIL}`);
  console.log("====================================");
});