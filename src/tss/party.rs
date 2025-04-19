impl BaseParty {
    pub fn is_running(&self) -> bool {
        self.rnd.is_some()
    }
}
