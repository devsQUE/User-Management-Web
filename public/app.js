// ============================================
// TVS Credit User Manager
// public/app.js
// ============================================

const SUPABASE_URL = "https://lzcbhleqlzetlvfykbsg.supabase.co";

const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_UCfpcxWqLmBU_303b2-dHw_LEwG8qRV";

const API_BASE = "/api";

// ============================================
// STATE
// ============================================

let accessToken = null;
let currentUser = null;
let users = [];
let editingUserId = null;
let deletingUserId = null;

// ============================================
// ELEMENTS
// ============================================

const loginScreen = document.getElementById("loginScreen");

const dashboardScreen = document.getElementById("dashboardScreen");

const loginForm = document.getElementById("loginForm");

const adminEmail = document.getElementById("adminEmail");

const adminPassword = document.getElementById("adminPassword");

const togglePassword = document.getElementById("togglePassword");

const loginError = document.getElementById("loginError");

const loginBtn = document.getElementById("loginBtn");

const adminEmailDisplay = document.getElementById("adminEmailDisplay");

const logoutBtn = document.getElementById("logoutBtn");

const totalUsers = document.getElementById("totalUsers");

const activeUsers = document.getElementById("activeUsers");

const disabledUsers = document.getElementById("disabledUsers");

const userSearch = document.getElementById("userSearch");

const usersTableBody = document.getElementById("usersTableBody");

const addUserBtn = document.getElementById("addUserBtn");

// ============================================
// USER MODAL
// ============================================

const userModal = document.getElementById("userModal");

const modalTitle = document.getElementById("modalTitle");

const modalDescription = document.getElementById("modalDescription");

const userForm = document.getElementById("userForm");

const editingUserIdInput = document.getElementById("editingUserId");

const userName = document.getElementById("userName");

const userEmail = document.getElementById("userEmail");

const userId = document.getElementById("userId");

const userPassword = document.getElementById("userPassword");

const userStatus = document.getElementById("userStatus");

const passwordHint = document.getElementById("passwordHint");

const userFormError = document.getElementById("userFormError");

const saveUserBtn = document.getElementById("saveUserBtn");

const closeModalBtn = document.getElementById("closeModalBtn");

const cancelUserBtn = document.getElementById("cancelUserBtn");

// ============================================
// DELETE MODAL
// ============================================

const deleteModal = document.getElementById("deleteModal");

const deleteUserName = document.getElementById("deleteUserName");

const cancelDeleteBtn = document.getElementById("cancelDeleteBtn");

const confirmDeleteBtn = document.getElementById("confirmDeleteBtn");

// ============================================
// SCREEN CONTROL
// ============================================

function showLogin() {
  if (loginScreen) {
    loginScreen.hidden = false;
  }

  if (dashboardScreen) {
    dashboardScreen.hidden = true;
  }
}

function showDashboard() {
  if (loginScreen) {
    loginScreen.hidden = true;
  }

  if (dashboardScreen) {
    dashboardScreen.hidden = false;
  }
}

// ============================================
// ERROR DISPLAY
// ============================================

function showLoginError(message) {
  if (!loginError) {
    return;
  }

  loginError.textContent = message || "";

  loginError.hidden = !message;
}

function showUserFormError(message) {
  if (!userFormError) {
    return;
  }

  userFormError.textContent = message || "";

  userFormError.hidden = !message;
}

// ============================================
// BUTTON LOADING
// ============================================

function setButtonLoading(button, loading, loadingText) {
  if (!button) {
    return;
  }

  if (loading) {
    if (!button.dataset.originalText) {
      button.dataset.originalText = button.textContent;
    }

    button.textContent = loadingText || "Loading...";

    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;

    button.disabled = false;
  }
}

// ============================================
// HTML ESCAPE
// ============================================

function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ============================================
// SUPABASE LOGIN
// ============================================

async function adminLogin(email, password) {
  const response = await fetch(
    `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",

        apikey: SUPABASE_PUBLISHABLE_KEY,
      },

      body: JSON.stringify({
        email,
        password,
      }),
    },
  );

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.error_description ||
        data.msg ||
        data.message ||
        "Invalid email or password.",
    );
  }

  if (!data.access_token) {
    throw new Error("Supabase did not return an access token.");
  }

  return data;
}

// ============================================
// API REQUEST
// ============================================

async function apiRequest(endpoint, options = {}) {
  if (!accessToken) {
    throw new Error("Admin session is missing.");
  }

  const headers = {
    ...(options.headers || {}),

    Authorization: `Bearer ${accessToken}`,
  };

  if (options.body) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (response.status === 401) {
    accessToken = null;
    currentUser = null;

    showLogin();

    throw new Error(data.message || "Admin session is invalid or expired.");
  }

  if (!response.ok) {
    throw new Error(data.message || data.error || "Server request failed.");
  }

  return data;
}

// ============================================
// LOGIN
// ============================================

loginForm?.addEventListener("submit", async function (event) {
  event.preventDefault();

  showLoginError("");

  const email = adminEmail?.value.trim();

  const password = adminPassword?.value || "";

  if (!email) {
    showLoginError("Please enter your email.");

    return;
  }

  if (!password) {
    showLoginError("Please enter your password.");

    return;
  }

  try {
    setButtonLoading(loginBtn, true, "Signing In...");

    console.log("[User Manager] Signing in...");

    const session = await adminLogin(email, password);

    accessToken = session.access_token;

    currentUser = session.user || {
      email,
    };

    console.log("[User Manager] Supabase login successful.");

    /*
     * Verify that the logged-in account
     * is actually the configured admin.
     */
    const result = await apiRequest("/users");

    users = Array.isArray(result.users) ? result.users : [];

    renderUsers();
    updateStats();

    if (adminEmailDisplay) {
      adminEmailDisplay.textContent = currentUser.email || email;
    }

    showDashboard();

    console.log("[User Manager] Admin dashboard loaded.");
  } catch (error) {
    console.error("[User Manager] Login error:", error);

    accessToken = null;
    currentUser = null;

    showLoginError(error.message || "Unable to sign in.");
  } finally {
    setButtonLoading(loginBtn, false);
  }
});

// ============================================
// PASSWORD TOGGLE
// ============================================

togglePassword?.addEventListener("click", function () {
  if (!adminPassword) {
    return;
  }

  if (adminPassword.type === "password") {
    adminPassword.type = "text";

    togglePassword.textContent = "Hide";
  } else {
    adminPassword.type = "password";

    togglePassword.textContent = "Show";
  }
});

// ============================================
// LOGOUT
// ============================================

function logout() {
  accessToken = null;
  currentUser = null;
  users = [];
  editingUserId = null;
  deletingUserId = null;

  if (adminPassword) {
    adminPassword.value = "";
  }

  if (usersTableBody) {
    usersTableBody.innerHTML = `
            <tr>
                <td
                    colspan="6"
                    class="empty-state"
                >
                    No users found.
                </td>
            </tr>
        `;
  }

  updateStats();

  closeUserModal();
  closeDeleteModal();

  showLogin();
}

logoutBtn?.addEventListener("click", logout);

// ============================================
// LOAD USERS
// ============================================

async function loadUsers() {
  const result = await apiRequest("/users");

  users = Array.isArray(result.users) ? result.users : [];

  renderUsers();
  updateStats();
}

// ============================================
// RENDER USERS
// ============================================

function renderUsers() {

    if (!usersTableBody) {
        return;
    }

    const search =
        userSearch?.value
            .trim()
            .toLowerCase() || "";

    const filtered =
        users.filter(function (user) {

            const name =
                String(
                    user.name || ""
                ).toLowerCase();

            const email =
                String(
                    user.email || ""
                ).toLowerCase();

            const uid =
                String(
                    user.userId || ""
                ).toLowerCase();

            return (
                name.includes(search) ||
                email.includes(search) ||
                uid.includes(search)
            );
        });


    if (!filtered.length) {

        usersTableBody.innerHTML = `
            <tr>
                <td
                    colspan="8"
                    class="empty-state"
                >
                    No users found.
                </td>
            </tr>
        `;

        return;
    }


    usersTableBody.innerHTML =
        filtered.map(function (user) {

            const status =
                user.status === "disabled"
                    ? "disabled"
                    : "active";


            const loginStatus =
                status === "disabled"
                    ? "disabled"
                    : user.loginStatus === "active"
                        ? "active"
                        : "logged-out";


            const initial =
                String(
                    user.name ||
                    user.userId ||
                    "U"
                )
                    .trim()
                    .charAt(0)
                    .toUpperCase();


            return `
                <tr>

                    <!-- USER -->
                    <td>
                        <div class="user-cell">

                            <div class="user-avatar">
                                ${escapeHTML(initial)}
                            </div>

                            <div class="user-info">

                                <div class="user-name">
                                    ${escapeHTML(
                                        user.name || "-"
                                    )}
                                </div>

                                <div class="user-id-small">
                                    User Account
                                </div>

                            </div>

                        </div>
                    </td>


                    <!-- USERNAME -->
                    <td>
                        <span class="username-text">
                            ${escapeHTML(
                                user.userId || "-"
                            )}
                        </span>
                    </td>


                    <!-- EMAIL -->
                    <td>
                        <span class="email-text">
                            ${escapeHTML(
                                user.email || "-"
                            )}
                        </span>
                    </td>


                    <!-- ACCOUNT STATUS -->
                    <td>
                        <span
                            class="status-badge ${status}"
                        >
                            <span class="status-dot"></span>

                            ${
                                status === "active"
                                    ? "Active"
                                    : "Disabled"
                            }
                        </span>
                    </td>


                    <!-- LOGIN STATUS -->
                    <td>
                        <span
                            class="login-status-badge ${loginStatus}"
                        >
                            <span class="status-dot"></span>

                            ${
                                loginStatus === "active"
                                    ? "Logged In"
                                    : loginStatus === "disabled"
                                        ? "Disabled"
                                        : "Logged Out"
                            }
                        </span>
                    </td>


                    <!-- LAST LOGIN -->
                    <td>
                        <div class="date-cell">
                            ${
                                user.lastSignInAt
                                    ? `
                                        <span class="date-main">
                                            ${formatDateTime(
                                                user.lastSignInAt
                                            )}
                                        </span>
                                    `
                                    : `
                                        <span class="never-login">
                                            Never
                                        </span>
                                    `
                            }
                        </div>
                    </td>


                    <!-- CREATED -->
                    <td>
                        <div class="date-cell">
                            <span class="date-main">
                                ${formatDate(
                                    user.createdAt
                                )}
                            </span>
                        </div>
                    </td>


                    <!-- ACTIONS -->
                    <td class="actions-column">

                        <div class="table-actions">

                            <button
                                type="button"
                                class="action-btn edit"
                                data-action="edit"
                                data-id="${escapeHTML(
                                    user.id
                                )}"
                                title="Edit user"
                                aria-label="Edit user"
                            >
                                <svg
                                    viewBox="0 0 24 24"
                                    aria-hidden="true"
                                >
                                    <path
                                        d="M12 20h9"
                                    />
                                    <path
                                        d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"
                                    />
                                </svg>
                            </button>


                            <button
                                type="button"
                                class="action-btn logout-user"
                                data-action="logout"
                                data-id="${escapeHTML(
                                    user.id
                                )}"
                                title="Log out user"
                                aria-label="Log out user"
                            >
                                <svg
                                    viewBox="0 0 24 24"
                                    aria-hidden="true"
                                >
                                    <path
                                        d="M10 17l5-5-5-5"
                                    />
                                    <path
                                        d="M15 12H3"
                                    />
                                    <path
                                        d="M21 19V5a2 2 0 0 0-2-2h-6"
                                    />
                                </svg>
                            </button>


                            <button
                                type="button"
                                class="action-btn delete"
                                data-action="delete"
                                data-id="${escapeHTML(
                                    user.id
                                )}"
                                title="Delete user"
                                aria-label="Delete user"
                            >
                                <svg
                                    viewBox="0 0 24 24"
                                    aria-hidden="true"
                                >
                                    <path
                                        d="M3 6h18"
                                    />
                                    <path
                                        d="M8 6V4h8v2"
                                    />
                                    <path
                                        d="M19 6l-1 14H6L5 6"
                                    />
                                    <path
                                        d="M10 11v5"
                                    />
                                    <path
                                        d="M14 11v5"
                                    />
                                </svg>
                            </button>

                        </div>

                    </td>

                </tr>
            `;

        }).join("");
}

// ============================================
// DATE
// ============================================

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function formatDateTime(value) {

    if (!value) {
        return "-";
    }

    const date = new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "-";
    }

    return date.toLocaleString(
        "en-IN",
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            hour12: true
        }
    );
}

// ============================================
// STATS
// ============================================

function updateStats() {
  const total = users.length;

  const active = users.filter((user) => user.status !== "disabled").length;

  const disabled = users.filter((user) => user.status === "disabled").length;

  if (totalUsers) {
    totalUsers.textContent = total;
  }

  if (activeUsers) {
    activeUsers.textContent = active;
  }

  if (disabledUsers) {
    disabledUsers.textContent = disabled;
  }
}

// ============================================
// SEARCH
// ============================================

userSearch?.addEventListener("input", function () {
  renderUsers();
});

// ============================================
// OPEN ADD USER
// ============================================

function openAddUserModal() {
  editingUserId = null;

  userForm?.reset();

  if (editingUserIdInput) {
    editingUserIdInput.value = "";
  }

  if (modalTitle) {
    modalTitle.textContent = "Add User";
  }

  if (modalDescription) {
    modalDescription.textContent = "Create a new TVS Credit Assistant user.";
  }

  if (saveUserBtn) {
    saveUserBtn.textContent = "Create User";
  }

  if (userPassword) {
    userPassword.required = true;
  }

  if (passwordHint) {
    passwordHint.textContent = "Required when creating a new user.";
  }

  showUserFormError("");

  if (userModal) {
    userModal.hidden = false;
  }
}

addUserBtn?.addEventListener("click", openAddUserModal);

// ============================================
// OPEN EDIT USER
// ============================================

function openEditUserModal(user) {
  editingUserId = user.id;

  if (editingUserIdInput) {
    editingUserIdInput.value = user.id;
  }

  if (modalTitle) {
    modalTitle.textContent = "Edit User";
  }

  if (modalDescription) {
    modalDescription.textContent = "Update this user's account information.";
  }

  if (saveUserBtn) {
    saveUserBtn.textContent = "Update User";
  }

  if (userName) {
    userName.value = user.name || "";
  }

  if (userEmail) {
    userEmail.value = user.email || "";
  }

  if (userId) {
    userId.value = user.userId || "";
  }

  if (userPassword) {
    userPassword.value = "";
    userPassword.required = false;
  }

  if (passwordHint) {
    passwordHint.textContent =
      "Leave password blank to keep the current password.";
  }

  if (userStatus) {
    userStatus.value = user.status === "disabled" ? "disabled" : "active";
  }

  showUserFormError("");

  if (userModal) {
    userModal.hidden = false;
  }
}

// ============================================
// CLOSE USER MODAL
// ============================================

function closeUserModal() {
  editingUserId = null;

  if (userModal) {
    userModal.hidden = true;
  }

  if (userForm) {
    userForm.reset();
  }

  showUserFormError("");
}

closeModalBtn?.addEventListener("click", closeUserModal);

cancelUserBtn?.addEventListener("click", closeUserModal);

// ============================================
// SAVE USER
// ============================================

userForm?.addEventListener("submit", async function (event) {
  event.preventDefault();

  showUserFormError("");

  const name = userName?.value.trim() || "";

  const email = userEmail?.value.trim() || "";

  const loginId = userId?.value.trim() || "";

  const password = userPassword?.value || "";

  const status = userStatus?.value || "active";

  if (!name) {
    showUserFormError("User name is required.");

    return;
  }

  if (!email) {
    showUserFormError("Email is required.");

    return;
  }

  if (!loginId) {
    showUserFormError("User ID is required.");

    return;
  }

  if (!editingUserId && !password) {
    showUserFormError("Password is required.");

    return;
  }

  const payload = {
    name,
    email,
    userId: loginId,
    status,
  };

  if (password) {
    payload.password = password;
  }

  try {
    setButtonLoading(
      saveUserBtn,
      true,
      editingUserId ? "Updating..." : "Creating...",
    );

    if (editingUserId) {
      await apiRequest(`/users/${encodeURIComponent(editingUserId)}`, {
        method: "PATCH",

        body: JSON.stringify(payload),
      });
    } else {
      await apiRequest("/users", {
        method: "POST",

        body: JSON.stringify(payload),
      });
    }

    closeUserModal();

    await loadUsers();
  } catch (error) {
    console.error("[User Manager] Save user error:", error);

    showUserFormError(error.message || "Unable to save user.");
  } finally {
    setButtonLoading(saveUserBtn, false);
  }
});

// ============================================
// TABLE ACTIONS
// ============================================

usersTableBody?.addEventListener("click", function (event) {
  const button = event.target.closest("[data-action]");

  if (!button) {
    return;
  }

  const action = button.dataset.action;

  const id = button.dataset.id;

  const user = users.find((item) => String(item.id) === String(id));

  if (!user) {
    return;
  }

  if (action === "edit") {
    openEditUserModal(user);
  }

  if (action === "logout") {
    logoutUser(user);
  }

  if (action === "delete") {
    openDeleteModal(user);
  }
});

// ============================================
// DELETE MODAL
// ============================================

function openDeleteModal(user) {
  deletingUserId = user.id;

  if (deleteUserName) {
    deleteUserName.textContent = user.name || user.email || "this user";
  }

  if (deleteModal) {
    deleteModal.hidden = false;
  }
}

function closeDeleteModal() {
  deletingUserId = null;

  if (deleteModal) {
    deleteModal.hidden = true;
  }
}

cancelDeleteBtn?.addEventListener("click", closeDeleteModal);

// ============================================
// CONFIRM DELETE
// ============================================

confirmDeleteBtn?.addEventListener("click", async function () {
  if (!deletingUserId) {
    return;
  }

  try {
    setButtonLoading(confirmDeleteBtn, true, "Deleting...");

    await apiRequest(`/users/${encodeURIComponent(deletingUserId)}`, {
      method: "DELETE",
    });

    closeDeleteModal();

    await loadUsers();
  } catch (error) {
    console.error("[User Manager] Delete error:", error);

    alert(error.message || "Unable to delete user.");
  } finally {
    setButtonLoading(confirmDeleteBtn, false);
  }
});

// --------------------------------------------
// Logout User
// --------------------------------------------

async function logoutUser(user) {
  const userName = user.name || user.userId || user.email || "this user";

  const confirmed = confirm(
    `Log out ${userName} from the TVS Credit Assistant extension?`,
  );

  if (!confirmed) {
    return;
  }

  try {
    /*
     * Server endpoint will be added
     * in the next step.
     */
    await apiRequest(`/users/${encodeURIComponent(user.id)}/logout`, {
      method: "POST",
    });

    alert(`${userName} has been logged out.`);

    await loadUsers();
  } catch (error) {
    console.error("[User Manager] Logout user error:", error);

    alert(error.message || "Unable to log out this user.");
  }
}

// ============================================
// MODAL OVERLAY CLICK
// ============================================

userModal?.addEventListener("click", function (event) {
  if (event.target.classList.contains("modal-overlay")) {
    closeUserModal();
  }
});

deleteModal?.addEventListener("click", function (event) {
  if (event.target.classList.contains("modal-overlay")) {
    closeDeleteModal();
  }
});

// ============================================
// INITIAL STATE
// ============================================

showLogin();

console.log("[TVS Credit User Manager] app.js loaded successfully.");
