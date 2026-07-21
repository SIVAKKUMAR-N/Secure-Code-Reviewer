/**
 * StorageAdapter
 * Abstract interface for report storage providers.
 */
class StorageAdapter {
  async save(scanData) {
    throw new Error('Method save() must be implemented');
  }

  async findById(id) {
    throw new Error('Method findById() must be implemented');
  }

  async getRecent(limit) {
    throw new Error('Method getRecent() must be implemented');
  }

  async getStats() {
    throw new Error('Method getStats() must be implemented');
  }
}

module.exports = StorageAdapter;
