// Supabase Client Initialization and Configuration
// This file initializes the Supabase client for use across the application

// Import Supabase library (assuming it's installed via npm or loaded from CDN)
// For npm: import { createClient } from '@supabase/supabase-js'
// For CDN: <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js"></script>

/**
 * Supabase Configuration
 * These values should be obtained from your Supabase project settings
 * https://app.supabase.com/project/[YOUR_PROJECT_ID]/settings/api
 */
const SUPABASE_URL = process.env.VITE_SUPABASE_URL || 'https://your-project.supabase.co';
const SUPABASE_ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || 'your-anon-key';

/**
 * Initialize Supabase Client
 * Creates a single instance of the Supabase client for the application
 */
const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

/**
 * Export the initialized Supabase client
 * This can be imported in other modules to use Supabase services
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { supabase };
}

// For ES modules
export { supabase };

/**
 * Supabase Service Methods
 * Common operations for interacting with Supabase
 */

/**
 * Get data from a table
 * @param {string} tableName - Name of the table
 * @param {object} options - Query options (select, filter, etc.)
 * @returns {Promise} Query result
 */
async function getFromTable(tableName, options = {}) {
  try {
    let query = supabase.from(tableName).select(options.select || '*');
    
    if (options.eq) {
      Object.entries(options.eq).forEach(([key, value]) => {
        query = query.eq(key, value);
      });
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    return { data, error: null };
  } catch (error) {
    console.error(`Error fetching from ${tableName}:`, error.message);
    return { data: null, error };
  }
}

/**
 * Insert data into a table
 * @param {string} tableName - Name of the table
 * @param {object} data - Data to insert
 * @returns {Promise} Insert result
 */
async function insertIntoTable(tableName, data) {
  try {
    const { data: result, error } = await supabase
      .from(tableName)
      .insert([data])
      .select();
    
    if (error) throw error;
    return { data: result, error: null };
  } catch (error) {
    console.error(`Error inserting into ${tableName}:`, error.message);
    return { data: null, error };
  }
}

/**
 * Update data in a table
 * @param {string} tableName - Name of the table
 * @param {object} updates - Data to update
 * @param {object} filters - Filter conditions
 * @returns {Promise} Update result
 */
async function updateInTable(tableName, updates, filters) {
  try {
    let query = supabase.from(tableName).update(updates);
    
    Object.entries(filters).forEach(([key, value]) => {
      query = query.eq(key, value);
    });
    
    const { data, error } = await query.select();
    
    if (error) throw error;
    return { data, error: null };
  } catch (error) {
    console.error(`Error updating ${tableName}:`, error.message);
    return { data: null, error };
  }
}

/**
 * Delete data from a table
 * @param {string} tableName - Name of the table
 * @param {object} filters - Filter conditions
 * @returns {Promise} Delete result
 */
async function deleteFromTable(tableName, filters) {
  try {
    let query = supabase.from(tableName).delete();
    
    Object.entries(filters).forEach(([key, value]) => {
      query = query.eq(key, value);
    });
    
    const { error } = await query;
    
    if (error) throw error;
    return { error: null };
  } catch (error) {
    console.error(`Error deleting from ${tableName}:`, error.message);
    return { error };
  }
}

/**
 * Authentication Methods
 */

/**
 * Sign up with email and password
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise} Auth result
 */
async function signUp(email, password) {
  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });
    
    if (error) throw error;
    return { data, error: null };
  } catch (error) {
    console.error('Sign up error:', error.message);
    return { data: null, error };
  }
}

/**
 * Sign in with email and password
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise} Auth result
 */
async function signIn(email, password) {
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    
    if (error) throw error;
    return { data, error: null };
  } catch (error) {
    console.error('Sign in error:', error.message);
    return { data: null, error };
  }
}

/**
 * Sign out current user
 * @returns {Promise} Sign out result
 */
async function signOut() {
  try {
    const { error } = await supabase.auth.signOut();
    
    if (error) throw error;
    return { error: null };
  } catch (error) {
    console.error('Sign out error:', error.message);
    return { error };
  }
}

/**
 * Get current user session
 * @returns {Promise} Current session
 */
async function getCurrentUser() {
  try {
    const { data: { user }, error } = await supabase.auth.getUser();
    
    if (error) throw error;
    return { user, error: null };
  } catch (error) {
    console.error('Get user error:', error.message);
    return { user: null, error };
  }
}

/**
 * Listen to authentication state changes
 * @param {function} callback - Callback function for state changes
 * @returns {function} Unsubscribe function
 */
function onAuthStateChange(callback) {
  return supabase.auth.onAuthStateChange((event, session) => {
    callback({ event, session });
  });
}

// Export helper functions
export {
  getFromTable,
  insertIntoTable,
  updateInTable,
  deleteFromTable,
  signUp,
  signIn,
  signOut,
  getCurrentUser,
  onAuthStateChange,
};
