//! Map and set aliases: fast hashing under `std`, ordered fallback
//! under `no_std`.
//!
//! Internal collections need determinism only up to the values they
//! produce — verdicts are value-determined, and canonical *ordering*
//! is imposed at the spec-mandated boundaries (wire hash sets are
//! sorted by construction, rendered lists sort at render). So the hot
//! path gets a hash map where one exists, and `no_std` builds fall
//! back to the ordered map `alloc` provides.
//!
//! Construct via [`Default`], which both variants provide (avoiding
//! the `new()`-availability asymmetry between them).

/// Key-value map.
#[cfg(feature = "std")]
pub type Map<K, V> = std::collections::HashMap<K, V>;

/// Key-value map.
#[cfg(not(feature = "std"))]
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

/// Value set.
#[cfg(feature = "std")]
pub type Set<T> = std::collections::HashSet<T>;

/// Value set.
#[cfg(not(feature = "std"))]
pub type Set<T> = alloc::collections::BTreeSet<T>;
