Agreed, and it was worse than described. Fixed in `657be2ca`.

The loss was happening at **registration**, not just at delivery. The `pushers` table only stored `data_url` and `data_format`, so custom members were discarded the moment a pusher was saved — the delivery-side reconstruction was a symptom rather than the cause. Preserving them therefore needed persistence work, not just a serialisation change.

Custom `data` members are now stored (migration `011_pushers_data_extra.sql`, schema version 11) and forwarded to the gateway intact, excluding only `url` per spec. Covered by a store round-trip test and a gateway-delivery test asserting the custom members arrive unmodified.
