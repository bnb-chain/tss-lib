use k256::ProjectivePoint;

let generator = ProjectivePoint::generator();
let child_public_key = self.public_key.add(&generator.mul(il))?;
