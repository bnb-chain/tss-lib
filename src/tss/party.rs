impl BaseParty {
    pub fn running(&self) -> bool {
        self.rnd.is_some()
    }
}
