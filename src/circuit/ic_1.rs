use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::data::csr::CsrValue;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_BYTES: usize = 6;
const MAX_PERSON_ID: u64 = 100000000000000;

/*
:param [{ personId, firstName }] => { RETURN
  4398046511333 AS personId,
  "Jose" AS firstName

MATCH (p:Person {id: $personId}), (friend:Person {firstName: $firstName})
       WHERE NOT p=friend
       WITH p, friend
       MATCH path = shortestPath((p)-[:KNOWS*1..3]-(friend))
       WITH min(length(path)) AS distance, friend
ORDER BY
    distance ASC,
    friend.lastName ASC,
    toInteger(friend.id) ASC
LIMIT 20

MATCH (friend)-[:IS_LOCATED_IN]->(friendCity:City)
OPTIONAL MATCH (friend)-[studyAt:STUDY_AT]->(uni:University)-[:IS_LOCATED_IN]->(uniCity:City)
WITH friend, collect(
    CASE uni.name
        WHEN null THEN null
        ELSE [uni.name, studyAt.classYear, uniCity.name]
    END ) AS unis, friendCity, distance

OPTIONAL MATCH (friend)-[workAt:WORK_AT]->(company:Company)-[:IS_LOCATED_IN]->(companyCountry:Country)
WITH friend, collect(
    CASE company.name
        WHEN null THEN null
        ELSE [company.name, workAt.workFrom, companyCountry.name]
    END ) AS companies, unis, friendCity, distance

RETURN
    friend.id AS friendId,
    friend.lastName AS friendLastName,
    distance AS distanceFromPerson,
    friend.birthday AS friendBirthday,
    friend.creationDate AS friendCreationDate,
    friend.gender AS friendGender,
    friend.browserUsed AS friendBrowserUsed,
    friend.locationIP AS friendLocationIp,
    friend.email AS friendEmails, // person_email_emailaddress_0_0.csv
    friend.speaks AS friendLanguages, // person_speaks_language_0_0.csv
    friendCity.name AS friendCityName, // person_isLocatedIn_place_0_0.csv + place_0_0.csv
    unis AS friendUniversities, // person_studyAt_organisation_0_0.csv
    companies AS friendCompanies // person_workAt_organisation_0_0.csv
ORDER BY
    distanceFromPerson ASC,
    friendLastName ASC,
    toInteger(friendId) ASC
LIMIT 20
*/

#[derive(Clone, Debug)]
pub struct ic1CircuitConfig<F: Field + Ord> {
    q_person: Selector,
    q_pre_lookup: Selector,

    person: Vec<Column<Advice>>,
    person_id: Column<Advice>,
    person_id_check: Column<Advice>,

    // node
    person_dist: Column<Advice>,
    predecessor: Column<Advice>,
    predecessor_dist: Column<Advice>,
    person_zero: crate::chips::is_zero::IsZeroConfig<F>,

    person_knows_person: Vec<Column<Advice>>,

    pkp_norm_0: Column<Advice>, // min(person_knows_person[0], person_knows_person[1])
    pkp_norm_1: Column<Advice>, // max(person_knows_person[0], person_knows_person[1])
    pkp_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>, // verify pkp_norm_0 <= pkp_norm_1

    pc_norm_0: Column<Advice>, // min(predecessor, person[0])
    pc_norm_1: Column<Advice>, // max(predecessor, person[0])
    pc_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>, // verify pc_norm_0 <= pc_norm_1

    // edge
    source_dist: Column<Advice>,
    target_dist: Column<Advice>,
    target_less: LtEqGenericConfig<F, NUM_BYTES>,
    q_target_less: Selector,
    q_edge: Selector,
    q_edge_exists: Vec<Selector>,

    person_firstname: Column<Advice>,

    // id | firstname | lastname | gender | birthday | creationDate | locationIP | browserUsed | CityId | Cityname | distance |
    top20_friends: Vec<Column<Advice>>,
    q_top20: Selector,

    person_isLocatedIn_place: Vec<Column<Advice>>,
    q_located: Selector,
    place: Vec<Column<Advice>>,
    q_place: Selector,

    top_20_paris_lookup_table: Vec<Column<Advice>>,
    // top20 personid + 0 + MAX_PERSON_ID
    top20_ext: Column<Advice>,
    top20_ext_order: LtEqGenericConfig<F, NUM_BYTES>,
    q_top20_ext: Selector,
    q_top20_ext_internal: Selector,
    q_top20_ext_boundary: Selector,
    q_top20_ext_order: Selector,
    q_top20_ext_lookup_table: Selector,

    // email
    person_email_emailaddress: Vec<Column<Advice>>,
    ordered_person_email_emailaddress: Vec<Column<Advice>>,
    ordered_person_email_configure: LtEqGenericConfig<F, NUM_BYTES>,
    q_ordered_email: Selector,
    aligned_email_personid: Column<Advice>,
    next_aligned_email_personid: Column<Advice>,
    q_email: Selector,
    email_flag: Column<Advice>,
    email_zero: crate::chips::is_zero::IsZeroConfig<F>,

    // language
    person_speaks_language: Vec<Column<Advice>>,
    q_language: Selector,
    ordered_person_speaks_language: Vec<Column<Advice>>,
    ordered_person_speaks_language_configure: LtEqGenericConfig<F, NUM_BYTES>,
    q_ordered_language: Selector,
    aligned_language_personid: Column<Advice>,
    next_aligned_language_personid: Column<Advice>,
    language_flag: Column<Advice>,
    language_zero: crate::chips::is_zero::IsZeroConfig<F>,

    // universities
    person_studyAt_organisation: Vec<Column<Advice>>,
    q_university: Selector,
    ordered_person_studyAt_organisation: Vec<Column<Advice>>,
    ordered_person_studyAt_organisation_configure: LtEqGenericConfig<F, NUM_BYTES>,
    q_ordered_university: Selector,
    aligned_university_personid: Column<Advice>,
    next_aligned_university_personid: Column<Advice>,
    university_flag: Column<Advice>,
    university_zero: crate::chips::is_zero::IsZeroConfig<F>,
    top_universities: Vec<Column<Advice>>,
    q_top_universities: Selector,
    q_ordered_uni_flag: Selector,

    // company
    person_workAt_organisation: Vec<Column<Advice>>,
    q_company: Selector,
    ordered_person_workAt_organisation: Vec<Column<Advice>>,
    ordered_person_workAt_organisation_configure: LtEqGenericConfig<F, NUM_BYTES>,
    q_ordered_company: Selector,
    aligned_company_personid: Column<Advice>,
    next_aligned_company_personid: Column<Advice>,
    company_flag: Column<Advice>,
    company_zero: crate::chips::is_zero::IsZeroConfig<F>,
    align_company_less: LtEqGenericConfig<F, NUM_BYTES>,
    next_align_company_larger: LtEqGenericConfig<F, NUM_BYTES>,
    top_companies: Vec<Column<Advice>>,
    q_top_companies: Selector,
    q_ordered_com_flag: Selector,

    align_email_less: LtEqGenericConfig<F, NUM_BYTES>,
    next_align_email_larger: LtEqGenericConfig<F, NUM_BYTES>,
    align_language_less: LtEqGenericConfig<F, NUM_BYTES>,
    next_align_language_larger: LtEqGenericConfig<F, NUM_BYTES>,
    align_university_less: LtEqGenericConfig<F, NUM_BYTES>,
    next_align_university_larger: LtEqGenericConfig<F, NUM_BYTES>,

    organisation: Vec<Column<Advice>>,
    q_organisation: Selector,

    organisation_isLocatedIn_place: Vec<Column<Advice>>,
    q_org_located: Selector,

    top20_order_less_dist: LtEqGenericConfig<F, NUM_BYTES>,
    top20_dist_eq: crate::chips::is_zero::IsZeroConfig<F>,
    top20_dist_flag: Column<Advice>,
    top20_order_equal_dist_less_lastname: LtEqGenericConfig<F, NUM_BYTES>,
    top20_lastname_eq: crate::chips::is_zero::IsZeroConfig<F>,
    top20_lastname_flag: Column<Advice>,
    top20_order_equal_dist_equal_lastname_less_id: LtEqGenericConfig<F, NUM_BYTES>,
    q_top20_order: Selector,

    q_candidate_check: Selector,
    candidate_vs_last_dist: LtEqGenericConfig<F, NUM_BYTES>,
    candvslast_dist_eq: crate::chips::is_zero::IsZeroConfig<F>,
    candvslast_dist_flag: Column<Advice>,
    candidate_vs_last_lastname: LtEqGenericConfig<F, NUM_BYTES>,
    candvslast_lastname_eq: crate::chips::is_zero::IsZeroConfig<F>,
    candvslast_lastname_flag: Column<Advice>,
    candidate_vs_last_id: LtEqGenericConfig<F, NUM_BYTES>,

    candidate_record: Vec<Column<Advice>>,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct ic1Chip<F: Field + Ord> {
    config: ic1CircuitConfig<F>,
}

impl<F: Field + Ord> ic1Chip<F> {
    pub fn construct(config: ic1CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> ic1CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let mut person = Vec::new();
        for _ in 0..8 {
            person.push(meta.advice_column());
        }

        let mut top20_friends = Vec::new();
        for _ in 0..11 {
            top20_friends.push(meta.advice_column());
        }
        meta.enable_equality(top20_friends[0]);

        let top20_ext = meta.advice_column();
        meta.enable_equality(top20_ext);

        let person_id = meta.advice_column();
        let person_id_check = meta.advice_column();
        meta.enable_equality(person_id_check);

        let q_person = meta.complex_selector();

        // construct IsZeroChip to verify person[0] == person_id
        let iz_person_advice = meta.advice_column();
        let person_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_person),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(person[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz_person_advice,
            person_id_check,
        );

        let person_dist = meta.advice_column();
        let predecessor = meta.advice_column();
        let predecessor_dist = meta.advice_column();

        // 1. predecessor + predecessor_dist --lookup--> person + person_dist
        let q_pre_lookup = meta.complex_selector();
        let one = Expression::Constant(F::ONE);
        meta.lookup_any(format!("predecessor + predecessor_dist"), |meta| {
            let q = meta.query_selector(q_pre_lookup);
            let a = meta.query_advice(predecessor, Rotation::cur());
            let b = meta.query_advice(predecessor_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // 2. if person_id_check == 1, dist == 0
        meta.create_gate("person_id_check * dist == 0", |meta| {
            let q = meta.query_selector(q_person);
            let person_id_check = meta.query_advice(person_id_check, Rotation::cur());
            let dist = meta.query_advice(person_dist, Rotation::cur());
            vec![q.clone() * person_id_check * dist]
        });

        // 3. node dist == predecessor dist + 1
        // the reason * (dist-4) is because we set the dummy and source's predecessor to 0
        meta.create_gate("dist == predecessor_dist + 1", |meta| {
            let q = meta.query_selector(q_person);
            let is_source = meta.query_advice(person_id_check, Rotation::cur());
            let dist = meta.query_advice(person_dist, Rotation::cur());
            let f_dist = meta.query_advice(predecessor_dist, Rotation::cur());
            vec![
                q.clone()
                    * (Expression::Constant(F::ONE) - is_source)
                    * (dist.clone() - f_dist.clone() - Expression::Constant(F::ONE))
                    * (dist - Expression::Constant(F::from(4u64))),
            ]
        });

        let mut person_knows_person = Vec::new();
        for _ in 0..2 {
            person_knows_person.push(meta.advice_column());
        }

        // initialize the normalized columns
        let pkp_norm_0 = meta.advice_column();
        let pkp_norm_1 = meta.advice_column();
        let pc_norm_0 = meta.advice_column();
        let pc_norm_1 = meta.advice_column();

        // 4.predecessor + person[0] --lookup--> person_knows_person
        let mut q_edge_exists = Vec::new();
        for _ in 0..2 {
            q_edge_exists.push(meta.complex_selector());
        }

        // normalize the pkp
        let pkp_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_edge_exists[1]),
            |meta| vec![meta.query_advice(pkp_norm_1, Rotation::cur())], // lhs = max_val
            |meta| vec![meta.query_advice(pkp_norm_0, Rotation::cur())], // rhs = min_val
        );
        meta.create_gate("pkp_normalization_check", |meta| {
            let q = meta.query_selector(q_edge_exists[1]);
            let u = meta.query_advice(person_knows_person[0], Rotation::cur());
            let v = meta.query_advice(person_knows_person[1], Rotation::cur());
            let norm_0 = meta.query_advice(pkp_norm_0, Rotation::cur()); // min(u,v)
            let norm_1 = meta.query_advice(pkp_norm_1, Rotation::cur()); // max(u,v)

            let order_check = pkp_norm_order_config.is_lt(meta, None);

            let sum_check = (norm_0.clone() + norm_1.clone()) - (u.clone() + v.clone());
            let prod_check = (norm_0 * norm_1) - (u * v);

            vec![
                q.clone() * sum_check,
                q.clone() * prod_check,
                q * order_check,
            ]
        });

        let pc_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_edge_exists[0]),
            |meta| vec![meta.query_advice(pc_norm_1, Rotation::cur())], // lhs = max_val
            |meta| vec![meta.query_advice(pc_norm_0, Rotation::cur())], // rhs = min_val
        );
        meta.create_gate("pc_normalization_check", |meta| {
            let q = meta.query_selector(q_edge_exists[0]);
            let p = meta.query_advice(predecessor, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let norm_0 = meta.query_advice(pc_norm_0, Rotation::cur()); // min(p,c)
            let norm_1 = meta.query_advice(pc_norm_1, Rotation::cur()); // max(p,c)

            let order_check = pc_norm_order_config.is_lt(meta, None);
            let sum_check = (norm_0.clone() + norm_1.clone()) - (p.clone() + c.clone());
            let prod_check = (norm_0 * norm_1) - (p * c);

            vec![
                q.clone() * sum_check,
                q.clone() * prod_check,
                q * order_check,
            ]
        });

        // 4. (norm_P, norm_C) --lookup--> (norm_U, norm_V)
        meta.lookup_any("normalized_edge_lookup", |meta| {
            let q_pc_side = meta.query_selector(q_edge_exists[0]);
            let q_pkp_side = meta.query_selector(q_edge_exists[1]);

            let current_pc_norm_0 = meta.query_advice(pc_norm_0, Rotation::cur());
            let current_pc_norm_1 = meta.query_advice(pc_norm_1, Rotation::cur());

            let table_pkp_norm_0 = meta.query_advice(pkp_norm_0, Rotation::cur());
            let table_pkp_norm_1 = meta.query_advice(pkp_norm_1, Rotation::cur());

            vec![
                (
                    q_pc_side.clone() * one.clone(),
                    q_pkp_side.clone() * one.clone(),
                ),
                (
                    q_pc_side.clone() * current_pc_norm_0,
                    q_pkp_side.clone() * table_pkp_norm_0,
                ),
                (q_pc_side * current_pc_norm_1, q_pkp_side * table_pkp_norm_1),
            ]
        });

        let source_dist = meta.advice_column();
        let target_dist = meta.advice_column();

        // 5. dist(target) <= dist(source) + 1
        let q_target_less = meta.selector();
        let target_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_target_less),
            |meta| vec![meta.query_advice(target_dist, Rotation::cur())],
            |meta| {
                vec![meta.query_advice(source_dist, Rotation::cur()) + Expression::Constant(F::ONE)]
            },
        );
        meta.create_gate("verify target_less", |meta| {
            let q = meta.query_selector(q_target_less);
            vec![q.clone() * (target_less.is_lt(meta, None) - Expression::Constant(F::ONE))]
        });

        // 6. edge[0] + source_dist --lookup--> person + person_dist
        let q_edge = meta.complex_selector();
        meta.lookup_any(format!("source dist"), |meta| {
            let q = meta.query_selector(q_edge);
            let a = meta.query_advice(person_knows_person[0], Rotation::cur());
            let b = meta.query_advice(source_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // 7. edge[1] + target_dist --lookup--> person + person_dist
        meta.lookup_any(format!("target dist"), |meta| {
            let q = meta.query_selector(q_edge);
            let a = meta.query_advice(person_knows_person[1], Rotation::cur());
            let b = meta.query_advice(target_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // top 20 correctness
        let q_top20 = meta.complex_selector();
        meta.lookup_any(format!("top20 from person"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_person);
            let top0 = meta.query_advice(top20_friends[0], Rotation::cur()); // id
            let top1 = meta.query_advice(top20_friends[1], Rotation::cur()); // firstname
            let top2 = meta.query_advice(top20_friends[2], Rotation::cur()); // lastname
            let top3 = meta.query_advice(top20_friends[3], Rotation::cur()); // gender
            let top4 = meta.query_advice(top20_friends[4], Rotation::cur()); // birthday
            let top5 = meta.query_advice(top20_friends[5], Rotation::cur()); // creationDate
            let top6 = meta.query_advice(top20_friends[6], Rotation::cur()); // locationIP
            let top7 = meta.query_advice(top20_friends[7], Rotation::cur()); // browserUsed
            let person0 = meta.query_advice(person[0], Rotation::cur());
            let person1 = meta.query_advice(person[1], Rotation::cur());
            let person2 = meta.query_advice(person[2], Rotation::cur());
            let person3 = meta.query_advice(person[3], Rotation::cur());
            let person4 = meta.query_advice(person[4], Rotation::cur());
            let person5 = meta.query_advice(person[5], Rotation::cur());
            let person6 = meta.query_advice(person[6], Rotation::cur());
            let person7 = meta.query_advice(person[7], Rotation::cur());
            let lhs = [one.clone(), top0, top1, top2, top3, top4, top5, top6, top7]
                .map(|c| c * q1.clone());
            let rhs = [
                one.clone(),
                person0,
                person1,
                person2,
                person3,
                person4,
                person5,
                person6,
                person7,
            ]
            .map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut person_email_emailaddress = Vec::new();
        for _ in 0..2 {
            person_email_emailaddress.push(meta.advice_column());
        }
        let q_email = meta.complex_selector();

        let mut person_speaks_language = Vec::new();
        for _ in 0..2 {
            person_speaks_language.push(meta.advice_column());
        }
        let q_language = meta.complex_selector();

        let mut person_isLocatedIn_place = Vec::new();
        for _ in 0..2 {
            person_isLocatedIn_place.push(meta.advice_column());
        }
        let q_located = meta.complex_selector();
        meta.lookup_any(format!("top20 CityId"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_located);
            let a = meta.query_advice(top20_friends[0], Rotation::cur()); // id
            let b = meta.query_advice(top20_friends[8], Rotation::cur()); // CityId
            let c = meta.query_advice(person_isLocatedIn_place[0], Rotation::cur()); // id
            let d = meta.query_advice(person_isLocatedIn_place[1], Rotation::cur()); // CityId
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut place = Vec::new();
        for _ in 0..2 {
            place.push(meta.advice_column());
        }
        let q_place = meta.complex_selector();
        meta.lookup_any(format!("top20 place"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_place);
            let a = meta.query_advice(top20_friends[8], Rotation::cur()); // CityId
            let b = meta.query_advice(top20_friends[9], Rotation::cur()); // City
            let c = meta.query_advice(place[0], Rotation::cur()); // CityId
            let d = meta.query_advice(place[1], Rotation::cur()); // City
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut person_studyAt_organisation = Vec::new();
        for _ in 0..3 {
            person_studyAt_organisation.push(meta.advice_column());
        }
        let q_university = meta.complex_selector();

        let mut person_workAt_organisation = Vec::new();
        for _ in 0..3 {
            person_workAt_organisation.push(meta.advice_column());
        }
        let q_company = meta.complex_selector();

        meta.lookup_any(format!("top20 distance"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_person);
            let a = meta.query_advice(top20_friends[0], Rotation::cur()); // Id
            let b = meta.query_advice(top20_friends[10], Rotation::cur()); // distance
            let c = meta.query_advice(person[0], Rotation::cur()); // Id
            let d = meta.query_advice(person_dist, Rotation::cur()); // distance
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let person_firstname = meta.advice_column();
        meta.create_gate("top20 firstname", |meta| {
            let q = meta.query_selector(q_top20);
            let a = meta.query_advice(top20_friends[1], Rotation::cur()); // firstname
            let b = meta.query_advice(person_firstname, Rotation::cur()); // firstname
            vec![q.clone() * (a - b)]
        });

        // verify top20_extension is sorted
        let q_top20_ext_order = meta.complex_selector();
        let q_top20_ext_lookup_table = meta.complex_selector();
        let q_top20_ext = meta.complex_selector();
        let q_top20_ext_internal = meta.complex_selector();
        let q_top20_ext_boundary = meta.complex_selector();
        let top20_ext_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_ext_order),
            |meta| vec![meta.query_advice(top20_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(top20_ext, Rotation::next())],
        );
        meta.create_gate("verify top20_ext_order", |meta| {
            let q = meta.query_selector(q_top20_ext_order);
            vec![q.clone() * (top20_ext_order.is_lt(meta, None) - Expression::Constant(F::ONE))]
        });
        meta.shuffle(format!("lookup top20_ext"), |meta| {
            let q1 = meta.query_selector(q_top20_ext_internal);
            let q2 = meta.query_selector(q_top20);
            let a = meta.query_advice(top20_ext, Rotation::cur());
            let c = meta.query_advice(top20_friends[0], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), c].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.create_gate("verify top20_ext boundary", |meta| {
            let q = meta.query_selector(q_top20_ext_boundary);
            let a = meta.query_advice(top20_ext, Rotation::cur());
            vec![q.clone() * a.clone() * (a - Expression::Constant(F::from(MAX_PERSON_ID)))]
        });
        meta.create_gate("verify top20_ext selector", |meta| {
            let q = meta.query_selector(q_top20_ext);
            let q1 = meta.query_selector(q_top20_ext_internal);
            let q2 = meta.query_selector(q_top20_ext_boundary);
            vec![q.clone() * (q1 + q2 - Expression::Constant(F::ONE))]
        });

        // top_20_paris_lookup_table
        let mut top_20_paris_lookup_table = Vec::new();
        for _ in 0..2 {
            top_20_paris_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(top_20_paris_lookup_table[i]);
        }

        // top20email
        let mut ordered_person_email_emailaddress = Vec::new();
        for _ in 0..2 {
            ordered_person_email_emailaddress.push(meta.advice_column());
        }
        meta.shuffle(format!("email shuffle"), |meta| {
            let q = meta.query_selector(q_email);
            let a = meta.query_advice(ordered_person_email_emailaddress[0], Rotation::cur());
            let b = meta.query_advice(ordered_person_email_emailaddress[1], Rotation::cur());
            let c = meta.query_advice(person_email_emailaddress[0], Rotation::cur());
            let d = meta.query_advice(person_email_emailaddress[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        let q_ordered_email = meta.selector();
        let ordered_person_email_configure = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_email),
            |meta| vec![meta.query_advice(ordered_person_email_emailaddress[0], Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_email_emailaddress[0], Rotation::next())],
        );
        meta.create_gate("verify ordered_person_email_configure", |meta| {
            let q = meta.query_selector(q_ordered_email);
            vec![
                q.clone()
                    * (ordered_person_email_configure.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let aligned_email_personid = meta.advice_column();
        let next_aligned_email_personid = meta.advice_column();
        meta.lookup_any(format!("align[i] from top20_ext"), |meta| {
            let q = meta.query_selector(q_email);
            let a = meta.query_advice(aligned_email_personid, Rotation::cur());
            let b = meta.query_advice(top20_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        // align[i] <= ordered_person_email_emailaddress[0]
        let align_email_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_email),
            |meta| vec![meta.query_advice(aligned_email_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_email_emailaddress[0], Rotation::cur())],
        );
        meta.create_gate(
            "verify aligned_email_personid less than top20_ext",
            |meta| {
                let q = meta.query_selector(q_email);
                vec![
                    q.clone() * (align_email_less.is_lt(meta, None) - Expression::Constant(F::ONE)),
                ]
            },
        );
        // next_align_email_larger_chip <= next_align[i] - 1
        let next_align_email_larger = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_email),
            |meta| vec![meta.query_advice(ordered_person_email_emailaddress[0], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_email_personid, Rotation::cur())
                        - Expression::Constant(F::ONE),
                ]
            },
        );
        meta.create_gate(
            "verify next_aligned_email_personid larger than top20_ext",
            |meta| {
                let q = meta.query_selector(q_email);
                vec![
                    q.clone()
                        * (next_align_email_larger.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );
        // (align[i], next_align[i]) lookup from top_20_paris_lookup_table
        meta.lookup_any(format!("align[i] from top20_ext"), |meta| {
            let q1 = meta.query_selector(q_email);
            let q2 = meta.query_selector(q_top20_ext_lookup_table);
            let a = meta.query_advice(aligned_email_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_email_personid, Rotation::cur());
            let c = meta.query_advice(top_20_paris_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(top_20_paris_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let email_flag = meta.advice_column();
        let iz_email_advice = meta.advice_column();
        let email_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_email),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(aligned_email_personid, Rotation::cur())
                    - meta.query_advice(ordered_person_email_emailaddress[0], Rotation::cur())
            },
            iz_email_advice,
            email_flag,
        );

        // language flag
        let mut ordered_person_speaks_language = Vec::new();
        for _ in 0..2 {
            ordered_person_speaks_language.push(meta.advice_column());
        }
        meta.shuffle(format!("language shuffle"), |meta| {
            let q = meta.query_selector(q_language);
            let a = meta.query_advice(ordered_person_speaks_language[0], Rotation::cur());
            let b = meta.query_advice(ordered_person_speaks_language[1], Rotation::cur());
            let c = meta.query_advice(person_speaks_language[0], Rotation::cur());
            let d = meta.query_advice(person_speaks_language[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_language = meta.selector();
        let ordered_person_speaks_language_configure = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_language),
            |meta| vec![meta.query_advice(ordered_person_speaks_language[0], Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_speaks_language[0], Rotation::next())],
        );
        meta.create_gate("verify ordered_person_speaks_language_configure", |meta| {
            let q = meta.query_selector(q_ordered_language);
            vec![
                q.clone()
                    * (ordered_person_speaks_language_configure.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let aligned_language_personid = meta.advice_column();
        let next_aligned_language_personid = meta.advice_column();
        meta.lookup_any(format!("language align[i] from top20_ext"), |meta| {
            let q = meta.query_selector(q_language);
            let a = meta.query_advice(aligned_language_personid, Rotation::cur());
            let b = meta.query_advice(top20_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // align[i] <= ordered_person_speaks_language[0]
        let align_language_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_language),
            |meta| vec![meta.query_advice(aligned_language_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_speaks_language[0], Rotation::cur())],
        );
        meta.create_gate(
            "verify aligned_language_personid less than person_speaks",
            |meta| {
                let q = meta.query_selector(q_language);
                vec![
                    q.clone()
                        * (align_language_less.is_lt(meta, None) - Expression::Constant(F::ONE)),
                ]
            },
        );

        // next_align_language_larger_chip <= next_align[i] - 1
        let next_align_language_larger = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_language),
            |meta| vec![meta.query_advice(ordered_person_speaks_language[0], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_language_personid, Rotation::cur())
                        - Expression::Constant(F::ONE),
                ]
            },
        );
        meta.create_gate(
            "verify next_aligned_language_personid larger than person_speaks",
            |meta| {
                let q = meta.query_selector(q_language);
                vec![
                    q.clone()
                        * (next_align_language_larger.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );

        // (align[i], next_align[i]) lookup from top_20_paris_lookup_table
        meta.lookup_any(format!("language align from top20_ext_pairs"), |meta| {
            let q1 = meta.query_selector(q_language);
            let q2 = meta.query_selector(q_top20_ext_lookup_table);
            let a = meta.query_advice(aligned_language_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_language_personid, Rotation::cur());
            let c = meta.query_advice(top_20_paris_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(top_20_paris_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let language_flag = meta.advice_column();
        let iz_language_advice = meta.advice_column();
        let language_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_language),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(aligned_language_personid, Rotation::cur())
                    - meta.query_advice(ordered_person_speaks_language[0], Rotation::cur())
            },
            iz_language_advice,
            language_flag,
        );

        // university flag
        let mut ordered_person_studyAt_organisation = Vec::new();
        for _ in 0..3 {
            ordered_person_studyAt_organisation.push(meta.advice_column());
        }
        meta.shuffle(format!("university shuffle"), |meta| {
            let q = meta.query_selector(q_university);
            let a = meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur());
            let b = meta.query_advice(ordered_person_studyAt_organisation[1], Rotation::cur());
            let c = meta.query_advice(ordered_person_studyAt_organisation[2], Rotation::cur());
            let d = meta.query_advice(person_studyAt_organisation[0], Rotation::cur());
            let e = meta.query_advice(person_studyAt_organisation[1], Rotation::cur());
            let f = meta.query_advice(person_studyAt_organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b, c].map(|c| c * q.clone());
            let rhs = [one.clone(), d, e, f].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_university = meta.selector();
        let ordered_person_studyAt_organisation_configure = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_university),
            |meta| vec![meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::next())],
        );
        meta.create_gate(
            "verify ordered_person_studyAt_organisation_configure",
            |meta| {
                let q = meta.query_selector(q_ordered_university);
                vec![
                    q.clone()
                        * (ordered_person_studyAt_organisation_configure.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );

        let aligned_university_personid = meta.advice_column();
        let next_aligned_university_personid = meta.advice_column();
        meta.lookup_any(format!("university align[i] from top20_ext"), |meta| {
            let q = meta.query_selector(q_university);
            let a = meta.query_advice(aligned_university_personid, Rotation::cur());
            let b = meta.query_advice(top20_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // align[i] <= ordered_person_studyAt_organisation[0]
        let align_university_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_university),
            |meta| vec![meta.query_advice(aligned_university_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur())],
        );
        meta.create_gate(
            "verify aligned_university_personid less than person_speaks",
            |meta| {
                let q = meta.query_selector(q_university);
                vec![
                    q.clone()
                        * (align_university_less.is_lt(meta, None) - Expression::Constant(F::ONE)),
                ]
            },
        );

        // next_align_university_larger_chip <= next_align[i] - 1
        let next_align_university_larger = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_university),
            |meta| vec![meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_university_personid, Rotation::cur())
                        - Expression::Constant(F::ONE),
                ]
            },
        );
        meta.create_gate(
            "verify next_aligned_university_personid larger than person_speaks",
            |meta| {
                let q = meta.query_selector(q_university);
                vec![
                    q.clone()
                        * (next_align_university_larger.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );

        // (align[i], next_align[i]) lookup from top_20_paris_lookup_table
        meta.lookup_any(format!("university align from top20_ext_pairs"), |meta| {
            let q1 = meta.query_selector(q_university);
            let q2 = meta.query_selector(q_top20_ext_lookup_table);
            let a = meta.query_advice(aligned_university_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_university_personid, Rotation::cur());
            let c = meta.query_advice(top_20_paris_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(top_20_paris_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let university_flag = meta.advice_column();
        let iz_university_advice = meta.advice_column();
        let university_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_university),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(aligned_university_personid, Rotation::cur())
                    - meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur())
            },
            iz_university_advice,
            university_flag,
        );

        let mut top_universities = Vec::new();
        for _ in 0..6 {
            top_universities.push(meta.advice_column());
        }
        let q_top_universities = meta.complex_selector();
        let q_ordered_uni_flag = meta.complex_selector();
        meta.shuffle(format!("university top shuffle"), |meta| {
            let q1 = meta.query_selector(q_top_universities);
            let q2 = meta.query_selector(q_ordered_uni_flag);
            let a = meta.query_advice(top_universities[0], Rotation::cur());
            let b = meta.query_advice(top_universities[1], Rotation::cur());
            let c = meta.query_advice(top_universities[2], Rotation::cur());
            let d = meta.query_advice(ordered_person_studyAt_organisation[0], Rotation::cur());
            let e = meta.query_advice(ordered_person_studyAt_organisation[1], Rotation::cur());
            let f = meta.query_advice(ordered_person_studyAt_organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b, c].map(|c| c * q1.clone());
            let rhs = [one.clone(), d, e, f].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // company
        let mut ordered_person_workAt_organisation = Vec::new();
        for _ in 0..3 {
            ordered_person_workAt_organisation.push(meta.advice_column());
        }
        meta.shuffle(format!("company shuffle"), |meta| {
            let q = meta.query_selector(q_company);
            let a = meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur());
            let b = meta.query_advice(ordered_person_workAt_organisation[1], Rotation::cur());
            let c = meta.query_advice(ordered_person_workAt_organisation[2], Rotation::cur());
            let d = meta.query_advice(person_workAt_organisation[0], Rotation::cur());
            let e = meta.query_advice(person_workAt_organisation[1], Rotation::cur());
            let f = meta.query_advice(person_workAt_organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b, c].map(|c| c * q.clone());
            let rhs = [one.clone(), d, e, f].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_company = meta.selector();
        let ordered_person_workAt_organisation_configure = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_company),
            |meta| vec![meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_workAt_organisation[0], Rotation::next())],
        );
        meta.create_gate(
            "verify ordered_person_workAt_organisation_configure",
            |meta| {
                let q = meta.query_selector(q_ordered_company);
                vec![
                    q.clone()
                        * (ordered_person_workAt_organisation_configure.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );

        let aligned_company_personid = meta.advice_column();
        let next_aligned_company_personid = meta.advice_column();
        // align[i] must be in top20_ext, lookup
        meta.lookup_any(format!("company align[i] from top20_ext"), |meta| {
            let q = meta.query_selector(q_company);
            let a = meta.query_advice(aligned_company_personid, Rotation::cur());
            let b = meta.query_advice(top20_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // align[i] <= ordered_person_workAt_organisation[0]
        let align_company_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_company),
            |meta| vec![meta.query_advice(aligned_company_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur())],
        );
        meta.create_gate(
            "verify aligned_company_personid less than person_workAt",
            |meta| {
                let q = meta.query_selector(q_company);
                vec![
                    q.clone()
                        * (align_company_less.is_lt(meta, None) - Expression::Constant(F::ONE)),
                ]
            },
        );

        // next_align_company_larger <= next_align[i] - 1
        let next_align_company_larger = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_company),
            |meta| vec![meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_company_personid, Rotation::cur())
                        - Expression::Constant(F::ONE),
                ]
            },
        );
        meta.create_gate(
            "verify next_aligned_company_personid larger than person_workAt",
            |meta| {
                let q = meta.query_selector(q_company);
                vec![
                    q.clone()
                        * (next_align_company_larger.is_lt(meta, None)
                            - Expression::Constant(F::ONE)),
                ]
            },
        );

        // (align[i], next_align[i]) lookup from top_20_paris_lookup_table
        meta.lookup_any(format!("company align from top20_ext_pairs"), |meta| {
            let q1 = meta.query_selector(q_company);
            let q2 = meta.query_selector(q_top20_ext_lookup_table);
            let a = meta.query_advice(aligned_company_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_company_personid, Rotation::cur());
            let c = meta.query_advice(top_20_paris_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(top_20_paris_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let company_flag = meta.advice_column();
        let iz_company_advice = meta.advice_column();
        let company_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_company),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(aligned_company_personid, Rotation::cur())
                    - meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur())
            },
            iz_company_advice,
            company_flag,
        );
        let mut top_companies = Vec::new();
        for _ in 0..6 {
            top_companies.push(meta.advice_column());
        }
        let q_top_companies = meta.complex_selector();
        let q_ordered_com_flag = meta.complex_selector();
        meta.shuffle(format!("company top shuffle"), |meta| {
            let q1 = meta.query_selector(q_top_companies);
            let q2 = meta.query_selector(q_ordered_com_flag);
            let a = meta.query_advice(top_companies[0], Rotation::cur());
            let b = meta.query_advice(top_companies[1], Rotation::cur());
            let c = meta.query_advice(top_companies[2], Rotation::cur());
            let d = meta.query_advice(ordered_person_workAt_organisation[0], Rotation::cur());
            let e = meta.query_advice(ordered_person_workAt_organisation[1], Rotation::cur());
            let f = meta.query_advice(ordered_person_workAt_organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b, c].map(|c| c * q1.clone());
            let rhs = [one.clone(), d, e, f].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut organisation = Vec::new();
        for _ in 0..3 {
            organisation.push(meta.advice_column());
        }
        let q_organisation = meta.complex_selector();

        meta.lookup_any(format!("university organisation lookup"), |meta| {
            let q1 = meta.query_selector(q_top_universities);
            let q2 = meta.query_selector(q_organisation);
            let a = meta.query_advice(top_universities[1], Rotation::cur());
            let b = meta.query_advice(top_universities[3], Rotation::cur());
            let c = meta.query_advice(organisation[0], Rotation::cur());
            let d = meta.query_advice(organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.lookup_any(format!("company organisation lookup"), |meta| {
            let q1 = meta.query_selector(q_top_companies);
            let q2 = meta.query_selector(q_organisation);
            let a = meta.query_advice(top_companies[1], Rotation::cur());
            let b = meta.query_advice(top_companies[3], Rotation::cur());
            let c = meta.query_advice(organisation[0], Rotation::cur());
            let d = meta.query_advice(organisation[2], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut organisation_isLocatedIn_place = Vec::new();
        for _ in 0..2 {
            organisation_isLocatedIn_place.push(meta.advice_column());
        }
        let q_org_located = meta.complex_selector();
        meta.lookup_any(format!("university place lookup"), |meta| {
            let q1 = meta.query_selector(q_top_universities);
            let q2 = meta.query_selector(q_place);
            let a = meta.query_advice(top_universities[4], Rotation::cur());
            let b = meta.query_advice(top_universities[5], Rotation::cur());
            let c = meta.query_advice(place[0], Rotation::cur());
            let d = meta.query_advice(place[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any(format!("company place lookup"), |meta| {
            let q1 = meta.query_selector(q_top_companies);
            let q2 = meta.query_selector(q_place);
            let a = meta.query_advice(top_companies[4], Rotation::cur());
            let b = meta.query_advice(top_companies[5], Rotation::cur());
            let c = meta.query_advice(place[0], Rotation::cur());
            let d = meta.query_advice(place[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any(format!("university location lookup"), |meta| {
            let q1 = meta.query_selector(q_top_universities);
            let q2 = meta.query_selector(q_org_located);
            let a = meta.query_advice(top_universities[1], Rotation::cur());
            let b = meta.query_advice(top_universities[4], Rotation::cur());
            let c = meta.query_advice(organisation_isLocatedIn_place[0], Rotation::cur());
            let d = meta.query_advice(organisation_isLocatedIn_place[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any(format!("company location lookup"), |meta| {
            let q1 = meta.query_selector(q_top_companies);
            let q2 = meta.query_selector(q_org_located);
            let a = meta.query_advice(top_companies[1], Rotation::cur());
            let b = meta.query_advice(top_companies[4], Rotation::cur());
            let c = meta.query_advice(organisation_isLocatedIn_place[0], Rotation::cur());
            let d = meta.query_advice(organisation_isLocatedIn_place[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_top20_order = meta.selector();

        let top20_order_less_dist = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| vec![meta.query_advice(top20_friends[10], Rotation::cur())],
            |meta| vec![meta.query_advice(top20_friends[10], Rotation::next())],
        );

        let top20_order_equal_dist_less_lastname = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| vec![meta.query_advice(top20_friends[2], Rotation::cur())],
            |meta| vec![meta.query_advice(top20_friends[2], Rotation::next())],
        );

        let top20_order_equal_dist_equal_lastname_less_id = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| vec![meta.query_advice(top20_friends[0], Rotation::cur())],
            |meta| vec![meta.query_advice(top20_friends[0], Rotation::next())],
        );

        let iz1 = meta.advice_column();
        let top20_dist_flag = meta.advice_column();
        let top20_dist_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(top20_friends[10], Rotation::cur())
                    - meta.query_advice(top20_friends[10], Rotation::next())
            },
            iz1,
            top20_dist_flag,
        );

        let iz2 = meta.advice_column();
        let top20_lastname_flag = meta.advice_column();
        let top20_lastname_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(top20_friends[2], Rotation::cur())
                    - meta.query_advice(top20_friends[2], Rotation::next())
            },
            iz2,
            top20_lastname_flag,
        );

        meta.create_gate("verify TOP20 friends id order", |meta| {
            let q_top20_order = meta.query_selector(q_top20_order);
            let dist_lt = top20_order_less_dist.is_lt(meta, None);
            let dist_eq = meta.query_advice(top20_dist_flag, Rotation::cur());
            let lastname_lt = top20_order_equal_dist_less_lastname.is_lt(meta, None);
            let lastname_eq = meta.query_advice(top20_lastname_flag, Rotation::cur());
            let id_lt = top20_order_equal_dist_equal_lastname_less_id.is_lt(meta, None);

            vec![
                q_top20_order.clone() * (one.clone() - dist_lt.clone()),
                q_top20_order.clone() * dist_eq.clone() * (one.clone() - lastname_lt.clone()),
                q_top20_order * dist_eq.clone() * lastname_eq.clone() * (one.clone() - id_lt),
            ]
        });

        let q_candidate_check = meta.selector();

        let mut candidate_record = Vec::new();
        for _ in 0..3 {
            candidate_record.push(meta.advice_column());
        }

        let candidate_vs_last_dist = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_check),
            |meta| vec![meta.query_advice(top20_friends[10], Rotation(19))],
            |meta| vec![meta.query_advice(candidate_record[2], Rotation::cur())],
        );

        let candidate_vs_last_lastname = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_check),
            |meta| vec![meta.query_advice(top20_friends[2], Rotation(19))],
            |meta| vec![meta.query_advice(candidate_record[1], Rotation::cur())],
        );

        let candidate_vs_last_id = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_check),
            |meta| vec![meta.query_advice(top20_friends[0], Rotation(19))],
            |meta| vec![meta.query_advice(candidate_record[0], Rotation::cur())],
        );

        let iz3 = meta.advice_column();
        let candvslast_dist_flag = meta.advice_column();
        let candvslast_dist_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_check),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(top20_friends[10], Rotation(19))
                    - meta.query_advice(candidate_record[2], Rotation::cur())
            },
            iz3,
            candvslast_dist_flag,
        );

        let iz4 = meta.advice_column();
        let candvslast_lastname_flag = meta.advice_column();
        let candvslast_lastname_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_check),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(top20_friends[2], Rotation(19))
                    - meta.query_advice(candidate_record[1], Rotation::cur())
            },
            iz4,
            candvslast_lastname_flag,
        );

        meta.create_gate("verify limit 20", |meta| {
            let q = meta.query_selector(q_candidate_check);

            let is_dist_less = candidate_vs_last_dist.is_lt(meta, None);
            let is_dist_equal = meta.query_advice(candvslast_dist_flag, Rotation::cur());
            let is_lastname_less = candidate_vs_last_lastname.is_lt(meta, None);
            let is_lastname_equal = meta.query_advice(candvslast_lastname_flag, Rotation::cur());
            let is_id_less = candidate_vs_last_id.is_lt(meta, None);

            vec![
                q.clone() * (one.clone() - is_dist_less.clone()),
                q.clone() * is_dist_equal.clone() * (one.clone() - is_lastname_less.clone()),
                q * is_dist_equal.clone() * is_lastname_equal.clone() * (one - is_id_less),
            ]
        });

        ic1CircuitConfig {
            q_person,
            q_pre_lookup,
            person,
            person_id,
            person_id_check,
            person_dist,
            predecessor,
            predecessor_dist,
            person_zero,
            person_knows_person,
            source_dist,
            target_dist,
            target_less,
            q_target_less,
            q_edge,
            q_edge_exists,
            top20_friends,
            q_top20,
            person_email_emailaddress,
            q_email,
            person_speaks_language,
            q_language,
            person_isLocatedIn_place,
            q_located,
            place,
            q_place,
            person_studyAt_organisation,
            person_workAt_organisation,
            q_university,
            q_company,
            person_firstname,
            instance,
            top_20_paris_lookup_table,
            top20_ext,
            top20_ext_order,
            q_top20_ext_lookup_table,
            aligned_email_personid,
            next_aligned_email_personid,
            q_top20_ext_order,
            align_email_less,
            next_align_email_larger,
            ordered_person_email_emailaddress,
            ordered_person_email_configure,
            q_ordered_email,
            email_flag,
            email_zero,
            ordered_person_speaks_language,
            ordered_person_speaks_language_configure,
            q_ordered_language,
            aligned_language_personid,
            next_aligned_language_personid,
            language_flag,
            language_zero,
            align_language_less,
            next_align_language_larger,
            ordered_person_studyAt_organisation,
            ordered_person_studyAt_organisation_configure,
            q_ordered_university,
            aligned_university_personid,
            next_aligned_university_personid,
            university_flag,
            university_zero,
            align_university_less,
            next_align_university_larger,
            ordered_person_workAt_organisation,
            ordered_person_workAt_organisation_configure,
            q_ordered_company,
            aligned_company_personid,
            next_aligned_company_personid,
            company_flag,
            company_zero,
            align_company_less,
            next_align_company_larger,
            top_universities,
            q_top_universities,
            q_ordered_uni_flag,
            top_companies,
            q_top_companies,
            q_ordered_com_flag,
            organisation,
            q_organisation,
            organisation_isLocatedIn_place,
            q_org_located,
            pkp_norm_0,
            pkp_norm_1,
            pkp_norm_order_config,
            pc_norm_0,
            pc_norm_1,
            pc_norm_order_config,
            top20_order_less_dist,
            top20_order_equal_dist_less_lastname,
            top20_order_equal_dist_equal_lastname_less_id,
            q_top20_order,
            q_candidate_check,
            candidate_vs_last_dist,
            candidate_vs_last_lastname,
            candidate_vs_last_id,
            candidate_record,
            q_top20_ext,
            q_top20_ext_internal,
            q_top20_ext_boundary,
            top20_dist_eq,
            top20_dist_flag,
            top20_lastname_eq,
            top20_lastname_flag,
            candvslast_dist_eq,
            candvslast_dist_flag,
            candvslast_lastname_eq,
            candvslast_lastname_flag,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<u64>>,
        person_knows_person: Vec<Vec<u64>>,
        person_id_val: u64,
        person_firstname: u64,
        person_speaks_language: Vec<Vec<u64>>,
        person_email_emailaddress: Vec<Vec<u64>>,
        person_isLocatedIn_place: Vec<Vec<u64>>,
        place: Vec<Vec<u64>>,
        person_studyAt_organisation: Vec<Vec<u64>>,
        person_workAt_organisation: Vec<Vec<u64>>,
        organisation: Vec<Vec<u64>>,
        organisation_isLocatedIn_place: Vec<Vec<u64>>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        fn f_to_u64<F: Field>(f: &F) -> u64 {
            let repr_bytes = f.to_repr();
            let bytes_ref: &[u8] = repr_bytes.as_ref();
            if bytes_ref.len() < 8 {
                panic!("Field representation too small for u64 extraction");
            }
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&bytes_ref[0..8]);
            u64::from_le_bytes(u64_bytes)
        }

        fn generate_align(orign: &Vec<u64>, top20_extension: &Vec<u64>) -> Vec<u64> {
            let mut d = Vec::with_capacity(orign.len());

            for &a_val in orign {
                let mut max_b = top20_extension[0];

                for &b_val in top20_extension.iter().rev() {
                    if b_val <= a_val {
                        max_b = b_val;
                        break;
                    }
                }
                d.push(max_b);
            }
            d
        }

        fn generate_d_next(orign: &Vec<u64>, top20_extension: &Vec<u64>) -> Vec<u64> {
            let mut d = Vec::with_capacity(orign.len());

            for &a_val in orign {
                let mut max_b_idx = 0;
                let mut found = false;

                for (idx, &b_val) in top20_extension.iter().enumerate().rev() {
                    if b_val <= a_val {
                        max_b_idx = idx;
                        found = true;
                        break;
                    }
                }

                if found && max_b_idx < top20_extension.len() - 1 {
                    d.push(top20_extension[max_b_idx + 1]);
                } else {
                    d.push(top20_extension[max_b_idx]);
                    panic!("generate_d_next wrong!!!!!");
                }
            }
            d
        }

        fn get_first_column(matrix: &Vec<Vec<u64>>) -> Vec<u64> {
            matrix
                .iter()
                .filter_map(|row| row.get(0).cloned())
                .collect()
        }

        let mut person_id_check_bits = vec![false; person_table.len()];
        for (i, row) in person_table.iter().enumerate() {
            if row[0] == person_id_val {
                person_id_check_bits[i] = true;
            }
        }

        let top20_dist_chip = IsZeroChip::construct(self.config.top20_dist_eq.clone());
        let top20_lastname_chip = IsZeroChip::construct(self.config.top20_lastname_eq.clone());
        let candvslast_dist_chip = IsZeroChip::construct(self.config.candvslast_dist_eq.clone());
        let candvslast_lastname_chip =
            IsZeroChip::construct(self.config.candvslast_lastname_eq.clone());

        let chip_person_eq = IsZeroChip::construct(self.config.person_zero.clone());
        let target_less_chip = LtEqGenericChip::construct(self.config.target_less);
        target_less_chip.load(layouter).unwrap();
        let pkp_norm_order_chip =
            LtEqGenericChip::construct(self.config.pkp_norm_order_config.clone());
        pkp_norm_order_chip.load(layouter).unwrap();
        let pc_norm_order_chip =
            LtEqGenericChip::construct(self.config.pc_norm_order_config.clone());
        pc_norm_order_chip.load(layouter).unwrap();
        let top20_order_less_dist_chip =
            LtEqGenericChip::construct(self.config.top20_order_less_dist.clone());
        top20_order_less_dist_chip.load(layouter).unwrap();

        let top20_order_equal_dist_less_lastname_chip =
            LtEqGenericChip::construct(self.config.top20_order_equal_dist_less_lastname.clone());
        top20_order_equal_dist_less_lastname_chip
            .load(layouter)
            .unwrap();

        let top20_order_equal_dist_equal_lastname_less_id_chip = LtEqGenericChip::construct(
            self.config
                .top20_order_equal_dist_equal_lastname_less_id
                .clone(),
        );
        top20_order_equal_dist_equal_lastname_less_id_chip
            .load(layouter)
            .unwrap();

        let candidate_vs_last_dist_chip =
            LtEqGenericChip::construct(self.config.candidate_vs_last_dist.clone());
        candidate_vs_last_dist_chip.load(layouter).unwrap();

        let candidate_vs_last_lastname_chip =
            LtEqGenericChip::construct(self.config.candidate_vs_last_lastname.clone());
        candidate_vs_last_lastname_chip.load(layouter).unwrap();

        let candidate_vs_last_id_chip =
            LtEqGenericChip::construct(self.config.candidate_vs_last_id.clone());
        candidate_vs_last_id_chip.load(layouter).unwrap();

        let max_hops = 3;
        let dummy_distance_u64: u64 = (max_hops + 1) as u64;

        let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &person_knows_person {
            adj.entry(edge[0]).or_default().push(edge[1]);
            adj.entry(edge[1]).or_default().push(edge[0]);
        }

        let mut distances = HashMap::new();
        let mut predecessors = HashMap::new();
        let mut q = VecDeque::new();

        for p_row in &person_table {
            distances.insert(p_row[0], dummy_distance_u64);
        }

        if distances.contains_key(&person_id_val) {
            distances.insert(person_id_val, 0);
            q.push_back(person_id_val);
            predecessors.insert(person_id_val, person_id_val);
        } else {
            println!("person_id_val not found in person_table");
        }

        // BFS
        while let Some(u_id) = q.pop_front() {
            let dist_u = distances[&u_id];

            if dist_u >= max_hops {
                continue;
            }

            if let Some(neighbors) = adj.get(&u_id) {
                for &v_id in neighbors {
                    if distances
                        .get(&v_id)
                        .map_or(false, |&d| d == dummy_distance_u64)
                    {
                        distances.insert(v_id, dist_u + 1);
                        predecessors.insert(v_id, u_id);
                        q.push_back(v_id);
                    }
                }
            }
        }

        // distances.iter()
        //     .filter(|(_, &v)| v == 1)
        //     .for_each(|(k, _)| println!("distance=1 Key: {}", k));

        let mut all_candidates = Vec::new();
        for row in &person_table {
            let id = row[0];
            if id != person_id_val && row[1] == person_firstname {
                let dist = distances.get(&id).cloned().unwrap_or(dummy_distance_u64);
                if dist <= max_hops as u64 {
                    all_candidates.push((id, row[2], dist));
                }
            }
        }

        all_candidates.sort_by(|a, b| {
            a.2.cmp(&b.2)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.0.cmp(&b.0))
        });

        let top20_candidates = if all_candidates.len() > 20 {
            all_candidates[0..20].to_vec()
        } else {
            all_candidates.clone()
        };

        let remaining_candidates = if all_candidates.len() > 20 {
            all_candidates[20..].to_vec()
        } else {
            Vec::new()
        };

        let mut top20_extension = vec![0];
        let top20_ids_sorted: Vec<u64> = top20_candidates.iter().map(|(id, _, _)| *id).collect();
        top20_extension.extend(top20_ids_sorted.clone());
        top20_extension.push(MAX_PERSON_ID);
        top20_extension.sort();

        let mut ordered_person_email_emailaddress = person_email_emailaddress.to_vec();
        ordered_person_email_emailaddress.sort_by(|a, b| a[0].cmp(&b[0]));

        let mut email_personid = get_first_column(&ordered_person_email_emailaddress);
        let email_align = generate_align(&email_personid, &top20_extension);
        let next_email_align = generate_d_next(&email_personid, &top20_extension);
        assert_eq!(email_align.len(), person_email_emailaddress.len());

        let mut email_flag = vec![false; person_email_emailaddress.len()];
        for i in 0..person_email_emailaddress.len() {
            if top20_ids_sorted.contains(&person_email_emailaddress[i][0]) {
                email_flag[i] = true;
            }
        }
        let chip_email_zero = IsZeroChip::construct(self.config.email_zero.clone());

        let align_email_less_chip =
            LtEqGenericChip::construct(self.config.align_email_less.clone());
        align_email_less_chip.load(layouter).unwrap();
        let next_align_email_larger_chip =
            LtEqGenericChip::construct(self.config.next_align_email_larger.clone());
        next_align_email_larger_chip.load(layouter).unwrap();
        let top20_ext_order_chip = LtEqGenericChip::construct(self.config.top20_ext_order.clone());
        top20_ext_order_chip.load(layouter).unwrap();
        let ordered_person_email_chip =
            LtEqGenericChip::construct(self.config.ordered_person_email_configure.clone());
        ordered_person_email_chip.load(layouter).unwrap();

        let mut ordered_person_speaks_language = person_speaks_language.to_vec();
        ordered_person_speaks_language.sort_by(|a, b| a[0].cmp(&b[0]));

        let language_personid = get_first_column(&ordered_person_speaks_language);
        let language_align = generate_align(&language_personid, &top20_extension);
        let next_language_align = generate_d_next(&language_personid, &top20_extension);
        assert_eq!(language_align.len(), person_speaks_language.len());

        let mut language_flag = vec![false; person_speaks_language.len()];
        for i in 0..person_speaks_language.len() {
            if top20_ids_sorted.contains(&person_speaks_language[i][0]) {
                language_flag[i] = true;
            }
        }
        let chip_language_zero = IsZeroChip::construct(self.config.language_zero.clone());

        let align_language_less_chip =
            LtEqGenericChip::construct(self.config.align_language_less.clone());
        align_language_less_chip.load(layouter).unwrap();
        let next_align_language_larger_chip =
            LtEqGenericChip::construct(self.config.next_align_language_larger.clone());
        next_align_language_larger_chip.load(layouter).unwrap();
        let ordered_person_language_chip = LtEqGenericChip::construct(
            self.config.ordered_person_speaks_language_configure.clone(),
        );
        ordered_person_language_chip.load(layouter).unwrap();

        let mut ordered_person_studyAt_organisation = person_studyAt_organisation.to_vec();
        ordered_person_studyAt_organisation.sort_by(|a, b| a[0].cmp(&b[0]));

        let university_personid = get_first_column(&ordered_person_studyAt_organisation);
        let university_align = generate_align(&university_personid, &top20_extension);
        let next_university_align = generate_d_next(&university_personid, &top20_extension);
        assert_eq!(university_align.len(), person_studyAt_organisation.len());

        let mut university_flag = vec![false; person_studyAt_organisation.len()];
        for i in 0..person_studyAt_organisation.len() {
            if top20_ids_sorted.contains(&person_studyAt_organisation[i][0]) {
                university_flag[i] = true;
            }
        }
        let chip_university_zero = IsZeroChip::construct(self.config.university_zero.clone());

        let align_university_less_chip =
            LtEqGenericChip::construct(self.config.align_university_less.clone());
        align_university_less_chip.load(layouter).unwrap();
        let next_align_university_larger_chip =
            LtEqGenericChip::construct(self.config.next_align_university_larger.clone());
        next_align_university_larger_chip.load(layouter).unwrap();
        let ordered_person_university_chip = LtEqGenericChip::construct(
            self.config
                .ordered_person_studyAt_organisation_configure
                .clone(),
        );
        ordered_person_university_chip.load(layouter).unwrap();
        let mut top_universities_data = Vec::new();
        for (i, row) in ordered_person_studyAt_organisation.iter().enumerate() {
            if university_flag[i] {
                let mut university_row = row.clone();
                if let Some(org) = organisation.iter().find(|org_row| org_row[0] == row[1]) {
                    university_row.push(org[2]);
                } else {
                    university_row.push(0);
                }
                top_universities_data.push(university_row);
            }
        }

        let mut ordered_person_workAt_organisation = person_workAt_organisation.to_vec();
        ordered_person_workAt_organisation.sort_by(|a, b| a[0].cmp(&b[0]));

        let company_personid = get_first_column(&ordered_person_workAt_organisation);
        let company_align = generate_align(&company_personid, &top20_extension);
        let next_company_align = generate_d_next(&company_personid, &top20_extension);
        assert_eq!(company_align.len(), person_workAt_organisation.len());

        let mut company_flag = vec![false; person_workAt_organisation.len()];
        for i in 0..person_workAt_organisation.len() {
            if top20_ids_sorted.contains(&person_workAt_organisation[i][0]) {
                company_flag[i] = true;
            }
        }
        let chip_company_zero = IsZeroChip::construct(self.config.company_zero.clone());

        let align_company_less_chip =
            LtEqGenericChip::construct(self.config.align_company_less.clone());
        align_company_less_chip.load(layouter).unwrap();
        let next_align_company_larger_chip =
            LtEqGenericChip::construct(self.config.next_align_company_larger.clone());
        next_align_company_larger_chip.load(layouter).unwrap();
        let ordered_person_company_chip = LtEqGenericChip::construct(
            self.config
                .ordered_person_workAt_organisation_configure
                .clone(),
        );
        ordered_person_company_chip.load(layouter).unwrap();

        let mut top_companies_data = Vec::new();
        for (i, row) in ordered_person_workAt_organisation.iter().enumerate() {
            if company_flag[i] {
                let mut company_row = row.clone();
                if let Some(org) = organisation.iter().find(|org_row| org_row[0] == row[1]) {
                    company_row.push(org[2]);
                } else {
                    company_row.push(0);
                }
                top_companies_data.push(company_row);
            }
        }

        let mut org_to_place = HashMap::new();
        for row in &organisation_isLocatedIn_place {
            org_to_place.insert(row[0], row[1]);
        }
        let mut expanded_top_universities_data = Vec::new();
        for row in &top_universities_data {
            let mut expanded_row = row.clone();
            if let Some(&place_id) = org_to_place.get(&row[1]) {
                expanded_row.push(place_id);
                if let Some(place_info) = place.iter().find(|p| p[0] == place_id) {
                    expanded_row.push(place_info[1]);
                } else {
                    expanded_row.push(0);
                }
            } else {
                expanded_row.push(0);
                expanded_row.push(0);
            }
            expanded_top_universities_data.push(expanded_row);
        }
        let mut expanded_top_companies_data = Vec::new();
        for row in &top_companies_data {
            let mut expanded_row = row.clone();
            if let Some(&place_id) = org_to_place.get(&row[1]) {
                expanded_row.push(place_id);

                if let Some(place_info) = place.iter().find(|p| p[0] == place_id) {
                    expanded_row.push(place_info[1]);
                } else {
                    expanded_row.push(0);
                }
            } else {
                expanded_row.push(0);
                expanded_row.push(0);
            }
            expanded_top_companies_data.push(expanded_row);
        }

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;
                    self.config.q_pre_lookup.enable(&mut region, i)?;

                    for j in 0..8 {
                        region.assign_advice(
                            || format!("person col {} row {}", j, i),
                            self.config.person[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }

                    region.assign_advice(
                        || "person_check",
                        self.config.person_id_check,
                        i,
                        || Value::known(F::from(person_id_check_bits[i] as u64)),
                    )?;

                    region.assign_advice(
                        || format!("person id {}", i),
                        self.config.person_id,
                        i,
                        || Value::known(F::from(person_id_val)),
                    )?;

                    let diff = F::from(row[0]) - F::from(person_id_val);
                    chip_person_eq
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();

                    let calculated_dist = distances
                        .get(&row[0])
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    let person_dist_val = F::from(calculated_dist);

                    region.assign_advice(
                        || format!("person_dist for row {}", i),
                        self.config.person_dist,
                        i,
                        || Value::known(person_dist_val),
                    )?;

                    let (predecessor_val, predecessor_dist) = if row[0] == person_id_val {
                        // source node: predecessor is self, predecessor distance is 0
                        (row[0], F::ZERO)
                    } else if calculated_dist != dummy_distance_u64 {
                        self.config.q_edge_exists[0].enable(&mut region, i)?;
                        // reachable node (not the source node): predecessor is BFS found predecessor, predecessor distance is dist - 1
                        let pred_id = predecessors.get(&row[0]).cloned().unwrap();
                        (pred_id, F::from(calculated_dist - 1))
                    } else {
                        // dummy
                        (row[0], F::from(dummy_distance_u64))
                    };

                    region.assign_advice(
                        || format!("predecessor for row {}", i),
                        self.config.predecessor,
                        i,
                        || Value::known(F::from(predecessor_val)),
                    )?;
                    region.assign_advice(
                        || format!("predecessor_dist for row {}", i),
                        self.config.predecessor_dist,
                        i,
                        || Value::known(predecessor_dist),
                    )?;
                    // pc_norm_0, pc_norm_1 (P,C)
                    if row[0] != person_id_val && calculated_dist != dummy_distance_u64 {
                        self.config.q_edge_exists[0].enable(&mut region, i)?;

                        let p_val = predecessor_val;
                        let c_val = row[0];
                        let norm_p_val = std::cmp::min(p_val, c_val);
                        let norm_c_val = std::cmp::max(p_val, c_val);

                        region.assign_advice(
                            || "pc_norm_0",
                            self.config.pc_norm_0,
                            i,
                            || Value::known(F::from(norm_p_val)),
                        )?;
                        region.assign_advice(
                            || "pc_norm_1",
                            self.config.pc_norm_1,
                            i,
                            || Value::known(F::from(norm_c_val)),
                        )?;

                        pc_norm_order_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(norm_c_val)],
                                &[F::from(norm_p_val)],
                            )
                            .unwrap();
                    }
                }

                for (i, edge) in person_knows_person.iter().enumerate() {
                    self.config.q_edge_exists[1].enable(&mut region, i)?;
                    self.config.q_target_less.enable(&mut region, i)?;
                    self.config.q_edge.enable(&mut region, i)?;

                    let u_val = edge[0];
                    let v_val = edge[1];
                    let source_dist = distances.get(&u_val).cloned().unwrap();
                    let target_dist = distances.get(&v_val).cloned().unwrap();

                    region.assign_advice(
                        || format!("edge_source_node at {}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(F::from(u_val)),
                    )?;

                    region.assign_advice(
                        || format!("edge_target_node at {}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(F::from(v_val)),
                    )?;

                    // pkp_norm_0, pkp_norm_1 (U,V)
                    let norm_u_val = std::cmp::min(u_val, v_val);
                    let norm_v_val = std::cmp::max(u_val, v_val);
                    region.assign_advice(
                        || "pkp_norm_0",
                        self.config.pkp_norm_0,
                        i,
                        || Value::known(F::from(norm_u_val)),
                    )?;
                    region.assign_advice(
                        || "pkp_norm_1",
                        self.config.pkp_norm_1,
                        i,
                        || Value::known(F::from(norm_v_val)),
                    )?;

                    pkp_norm_order_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(norm_v_val)],
                            &[F::from(norm_u_val)],
                        )
                        .unwrap();

                    region.assign_advice(
                        || format!("source_dist for edge at {}", i),
                        self.config.source_dist,
                        i,
                        || Value::known(F::from(source_dist)),
                    )?;
                    region.assign_advice(
                        || format!("target_dist for edge at {}", i),
                        self.config.target_dist,
                        i,
                        || Value::known(F::from(target_dist)),
                    )?;

                    target_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(target_dist)],
                            &[F::from(source_dist) + F::ONE],
                        )
                        .unwrap();
                }

                for i in 0..top20_extension.len() {
                    self.config.q_top20_ext.enable(&mut region, i)?;
                    if i != top20_extension.len() - 1 {
                        self.config.q_top20_ext_order.enable(&mut region, i)?;
                        self.config
                            .q_top20_ext_lookup_table
                            .enable(&mut region, i)?;
                        top20_ext_order_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(top20_extension[i])],
                                &[F::from(top20_extension[i + 1])],
                            )
                            .unwrap();

                        region.assign_advice(
                            || format!("top_20_paris_lookup_table from top20"),
                            self.config.top_20_paris_lookup_table[0],
                            i,
                            || Value::known(F::from(top20_extension[i])),
                        )?;
                        if i != 0 {}
                    }
                    if i != 0 && i != top20_extension.len() - 1 {
                        self.config.q_top20_ext_internal.enable(&mut region, i)?;
                    } else {
                        self.config.q_top20_ext_boundary.enable(&mut region, i)?;
                    }

                    if i != 0 {
                        region.assign_advice(
                            || format!("top_20_paris_lookup_table from top20"),
                            self.config.top_20_paris_lookup_table[1],
                            i - 1,
                            || Value::known(F::from(top20_extension[i])),
                        )?;
                    }
                    self.config.q_top20_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("top20_extension from top20"),
                        self.config.top20_ext,
                        i,
                        || Value::known(F::from(top20_extension[i])),
                    )?;
                }

                for (i, (friend_id, last_name, distance)) in top20_candidates.iter().enumerate() {
                    self.config.q_top20.enable(&mut region, i)?;

                    let friend_row = person_table
                        .iter()
                        .find(|row| row[0] == *friend_id)
                        .expect("friend_id not found in person_table");

                    let cell_a = region.assign_advice(
                        || format!("top20 friend col {} row {}", 0, i),
                        self.config.top20_friends[0],
                        i,
                        || Value::known(F::from(friend_row[0])),
                    )?;
                    if i < top20_candidates.len() - 1 {
                        self.config.q_top20_order.enable(&mut region, i)?;

                        top20_order_less_dist_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(*distance)],
                                &[F::from(top20_candidates[i + 1].2)],
                            )
                            .unwrap();

                        if *distance == top20_candidates[i + 1].2 {
                            region.assign_advice(
                                || format!("date_check"),
                                self.config.top20_dist_flag,
                                i,
                                || Value::known(F::from(1u64)),
                            )?;
                        } else {
                            region.assign_advice(
                                || format!("date_check"),
                                self.config.top20_dist_flag,
                                i,
                                || Value::known(F::from(0u64)),
                            )?;
                        }

                        top20_dist_chip
                            .assign(
                                &mut region,
                                i,
                                Value::known(
                                    F::from(*distance) - F::from(top20_candidates[i + 1].2),
                                ),
                            )
                            .unwrap();

                        top20_order_equal_dist_less_lastname_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(*last_name)],
                                &[F::from(top20_candidates[i + 1].1)],
                            )
                            .unwrap();

                        if *last_name == top20_candidates[i + 1].1 {
                            region.assign_advice(
                                || format!("lastname_check"),
                                self.config.top20_lastname_flag,
                                i,
                                || Value::known(F::from(1u64)),
                            )?;
                        } else {
                            region.assign_advice(
                                || format!("lastname_check"),
                                self.config.top20_lastname_flag,
                                i,
                                || Value::known(F::from(0u64)),
                            )?;
                        }
                        top20_lastname_chip
                            .assign(
                                &mut region,
                                i,
                                Value::known(
                                    F::from(*last_name) - F::from(top20_candidates[i + 1].1),
                                ),
                            )
                            .unwrap();

                        top20_order_equal_dist_equal_lastname_less_id_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(*friend_id)],
                                &[F::from(top20_candidates[i + 1].0)],
                            )
                            .unwrap();
                    }

                    for j in 1..8 {
                        region.assign_advice(
                            || format!("top20 friend col {} row {}", j, i),
                            self.config.top20_friends[j],
                            i,
                            || Value::known(F::from(friend_row[j])),
                        )?;
                    }

                    region.assign_advice(
                        || format!("top20 friend distance row {}", i),
                        self.config.top20_friends[10],
                        i,
                        || Value::known(F::from(*distance)),
                    )?;

                    let friend_location = person_isLocatedIn_place
                        .iter()
                        .find(|loc| loc[0] == *friend_id);

                    if let Some(location) = friend_location {
                        self.config.q_located.enable(&mut region, i)?;
                        region.assign_advice(
                            || format!("top20 friend cityId row {}", i),
                            self.config.top20_friends[8],
                            i,
                            || Value::known(F::from(location[1])),
                        )?;

                        let city_info = place.iter().find(|p| p[0] == location[1]);

                        if let Some(city) = city_info {
                            self.config.q_place.enable(&mut region, i)?;
                            region.assign_advice(
                                || format!("top20 friend city name row {}", i),
                                self.config.top20_friends[9],
                                i,
                                || Value::known(F::from(city[1])),
                            )?;
                        }
                    }

                    region.assign_advice(
                        || format!("email person_id row {}", i),
                        self.config.person_firstname,
                        i,
                        || Value::known(F::from(person_firstname)),
                    )?;
                }

                assert_eq!(email_align.len(), person_email_emailaddress.len());
                assert_eq!(next_email_align.len(), person_email_emailaddress.len());
                for (i, ((row, &email_align_val), &next_email_align_val)) in
                    ordered_person_email_emailaddress
                        .iter()
                        .zip(email_align.iter())
                        .zip(next_email_align.iter())
                        .enumerate()
                {
                    self.config.q_email.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("email person_id row {}", i),
                        self.config.ordered_person_email_emailaddress[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("email address row {}", i),
                        self.config.ordered_person_email_emailaddress[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;

                    region.assign_advice(
                        || format!("aligned_email_personid row {}", i),
                        self.config.aligned_email_personid,
                        i,
                        || Value::known(F::from(email_align_val)),
                    )?;

                    align_email_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(email_align_val)], // lhs = next date
                            &[F::from(row[0])],          // rhs = current date
                        )
                        .unwrap();

                    region.assign_advice(
                        || format!("next_aligned_email_personid row {}", i),
                        self.config.next_aligned_email_personid,
                        i,
                        || Value::known(F::from(next_email_align_val)),
                    )?;
                    next_align_email_larger_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[0])], // lhs = next date
                            &[F::from(next_email_align_val) - F::ONE], // rhs = current date
                        )
                        .unwrap();
                    if i != ordered_person_email_emailaddress.len() - 1 {
                        self.config.q_ordered_email.enable(&mut region, i)?;
                        ordered_person_email_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[0])], // lhs = next date
                                &[F::from(ordered_person_email_emailaddress[i + 1][0])], // rhs = current date
                            )
                            .unwrap();
                    }

                    region.assign_advice(
                        || format!("next_aligned_email_personid row {}", i),
                        self.config.email_flag,
                        i,
                        || Value::known(F::from(email_flag[i] as u64)),
                    )?;
                    let diff = F::from(email_align_val) - F::from(row[0]);
                    chip_email_zero
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();
                }
                for (i, row) in person_email_emailaddress.iter().enumerate() {
                    region.assign_advice(
                        || format!("email person_id row {}", i),
                        self.config.person_email_emailaddress[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("email address row {}", i),
                        self.config.person_email_emailaddress[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                }

                assert_eq!(language_align.len(), person_speaks_language.len());
                assert_eq!(next_language_align.len(), person_speaks_language.len());
                for (i, ((row, &language_align_val), &next_language_align_val)) in
                    ordered_person_speaks_language
                        .iter()
                        .zip(language_align.iter())
                        .zip(next_language_align.iter())
                        .enumerate()
                {
                    self.config.q_language.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("language person_id row {}", i),
                        self.config.ordered_person_speaks_language[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("language address row {}", i),
                        self.config.ordered_person_speaks_language[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;

                    region.assign_advice(
                        || format!("aligned_language_personid row {}", i),
                        self.config.aligned_language_personid,
                        i,
                        || Value::known(F::from(language_align_val)),
                    )?;

                    align_language_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(language_align_val)], // lhs = next date
                            &[F::from(row[0])],             // rhs = current date
                        )
                        .unwrap();

                    region.assign_advice(
                        || format!("next_aligned_language_personid row {}", i),
                        self.config.next_aligned_language_personid,
                        i,
                        || Value::known(F::from(next_language_align_val)),
                    )?;
                    next_align_language_larger_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[0])], // lhs = next date
                            &[F::from(next_language_align_val) - F::ONE], // rhs = current date
                        )
                        .unwrap();
                    if i != ordered_person_speaks_language.len() - 1 {
                        self.config.q_ordered_language.enable(&mut region, i)?;
                        ordered_person_language_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[0])], // lhs = next date
                                &[F::from(ordered_person_speaks_language[i + 1][0])], // rhs = current date
                            )
                            .unwrap();
                    }

                    region.assign_advice(
                        || format!("next_aligned_language_personid row {}", i),
                        self.config.language_flag,
                        i,
                        || Value::known(F::from(language_flag[i] as u64)),
                    )?;
                    let diff = F::from(language_align_val) - F::from(row[0]);
                    chip_language_zero
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();
                }
                for (i, row) in person_speaks_language.iter().enumerate() {
                    region.assign_advice(
                        || format!("language person_id row {}", i),
                        self.config.person_speaks_language[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("language address row {}", i),
                        self.config.person_speaks_language[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                }

                for (i, row) in person_isLocatedIn_place.iter().enumerate() {
                    self.config
                        .q_located
                        .enable(&mut region, i + person_table.len())?;
                    region.assign_advice(
                        || format!("location person_id row {}", i),
                        self.config.person_isLocatedIn_place[0],
                        i + person_table.len(),
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("location place_id row {}", i),
                        self.config.person_isLocatedIn_place[1],
                        i + person_table.len(),
                        || Value::known(F::from(row[1])),
                    )?;
                }

                for (i, row) in place.iter().enumerate() {
                    self.config
                        .q_place
                        .enable(&mut region, i + person_table.len())?;
                    region.assign_advice(
                        || format!("place_id row {}", i),
                        self.config.place[0],
                        i + person_table.len(),
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("place_name row {}", i),
                        self.config.place[1],
                        i + person_table.len(),
                        || Value::known(F::from(row[1])),
                    )?;
                }

                assert_eq!(university_align.len(), person_studyAt_organisation.len());
                assert_eq!(
                    next_university_align.len(),
                    person_studyAt_organisation.len()
                );
                for (i, (((row, &university_align_val), &next_university_align_val), &flag)) in
                    ordered_person_studyAt_organisation
                        .iter()
                        .zip(university_align.iter())
                        .zip(next_university_align.iter())
                        .zip(university_flag.iter())
                        .enumerate()
                {
                    self.config.q_university.enable(&mut region, i)?;
                    if flag {
                        self.config.q_ordered_uni_flag.enable(&mut region, i)?;
                    }

                    region.assign_advice(
                        || format!("university person_id row {}", i),
                        self.config.ordered_person_studyAt_organisation[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("university address row {}", i),
                        self.config.ordered_person_studyAt_organisation[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("university address row {}", i),
                        self.config.ordered_person_studyAt_organisation[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;

                    region.assign_advice(
                        || format!("aligned_university_personid row {}", i),
                        self.config.aligned_university_personid,
                        i,
                        || Value::known(F::from(university_align_val)),
                    )?;

                    align_university_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(university_align_val)], // lhs = next date
                            &[F::from(row[0])],               // rhs = current date
                        )
                        .unwrap();

                    region.assign_advice(
                        || format!("next_aligned_university_personid row {}", i),
                        self.config.next_aligned_university_personid,
                        i,
                        || Value::known(F::from(next_university_align_val)),
                    )?;
                    next_align_university_larger_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[0])], // lhs = next date
                            &[F::from(next_university_align_val) - F::ONE], // rhs = current date
                        )
                        .unwrap();
                    if i != ordered_person_studyAt_organisation.len() - 1 {
                        self.config.q_ordered_university.enable(&mut region, i)?;
                        ordered_person_university_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[0])], // lhs = next date
                                &[F::from(ordered_person_studyAt_organisation[i + 1][0])], // rhs = current date
                            )
                            .unwrap();
                    }

                    region.assign_advice(
                        || format!("next_aligned_university_personid row {}", i),
                        self.config.university_flag,
                        i,
                        || Value::known(F::from(university_flag[i] as u64)),
                    )?;
                    let diff = F::from(university_align_val) - F::from(row[0]);
                    chip_university_zero
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();
                }
                for (i, row) in person_studyAt_organisation.iter().enumerate() {
                    region.assign_advice(
                        || format!("university person_id row {}", i),
                        self.config.person_studyAt_organisation[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("university address row {}", i),
                        self.config.person_studyAt_organisation[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("university address row {}", i),
                        self.config.person_studyAt_organisation[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;
                }
                for (i, row) in top_universities_data.iter().enumerate() {
                    self.config.q_top_universities.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("top_university person_id row {}", i),
                        self.config.top_universities[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;

                    region.assign_advice(
                        || format!("top_university org_id row {}", i),
                        self.config.top_universities[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("top_university class year row {}", i),
                        self.config.top_universities[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;
                    region.assign_advice(
                        || format!("top_university org_name row {}", i),
                        self.config.top_universities[3],
                        i,
                        || Value::known(F::from(row[3])),
                    )?;
                }

                assert_eq!(company_align.len(), person_workAt_organisation.len());
                assert_eq!(next_company_align.len(), person_workAt_organisation.len());
                for (i, (((row, &company_align_val), &next_company_align_val), &flag)) in
                    ordered_person_workAt_organisation
                        .iter()
                        .zip(company_align.iter())
                        .zip(next_company_align.iter())
                        .zip(company_flag.iter())
                        .enumerate()
                {
                    self.config.q_company.enable(&mut region, i)?;
                    if flag {
                        self.config.q_ordered_com_flag.enable(&mut region, i)?;
                    }

                    // Assign ordered_person_workAt_organisation
                    region.assign_advice(
                        || format!("company person_id row {}", i),
                        self.config.ordered_person_workAt_organisation[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("company org_id row {}", i),
                        self.config.ordered_person_workAt_organisation[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("company workfrom row {}", i),
                        self.config.ordered_person_workAt_organisation[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;

                    // Assign aligned_company_personid
                    region.assign_advice(
                        || format!("aligned_company_personid row {}", i),
                        self.config.aligned_company_personid,
                        i,
                        || Value::known(F::from(company_align_val)),
                    )?;

                    align_company_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(company_align_val)],
                            &[F::from(row[0])],
                        )
                        .unwrap();

                    // Assign next_aligned_company_personid
                    region.assign_advice(
                        || format!("next_aligned_company_personid row {}", i),
                        self.config.next_aligned_company_personid,
                        i,
                        || Value::known(F::from(next_company_align_val)),
                    )?;

                    next_align_company_larger_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[0])],
                            &[F::from(next_company_align_val) - F::ONE],
                        )
                        .unwrap();

                    if i != ordered_person_workAt_organisation.len() - 1 {
                        self.config.q_ordered_company.enable(&mut region, i)?;
                        ordered_person_company_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[0])],
                                &[F::from(ordered_person_workAt_organisation[i + 1][0])],
                            )
                            .unwrap();
                    }

                    region.assign_advice(
                        || format!("company_flag row {}", i),
                        self.config.company_flag,
                        i,
                        || Value::known(F::from(company_flag[i] as u64)),
                    )?;

                    let diff = F::from(company_align_val) - F::from(row[0]);
                    chip_company_zero
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();
                }

                for (i, row) in person_workAt_organisation.iter().enumerate() {
                    region.assign_advice(
                        || format!("company person_id row {}", i),
                        self.config.person_workAt_organisation[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("company org_id row {}", i),
                        self.config.person_workAt_organisation[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("company workfrom row {}", i),
                        self.config.person_workAt_organisation[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;
                }
                for (i, row) in top_companies_data.iter().enumerate() {
                    self.config.q_top_companies.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("top_company person_id row {}", i),
                        self.config.top_companies[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;

                    region.assign_advice(
                        || format!("top_company org_id row {}", i),
                        self.config.top_companies[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    region.assign_advice(
                        || format!("top_company workfrom row {}", i),
                        self.config.top_companies[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;
                    region.assign_advice(
                        || format!("top_company org_name row {}", i),
                        self.config.top_companies[3],
                        i,
                        || Value::known(F::from(row[3])),
                    )?;
                }
                for (i, row) in organisation.iter().enumerate() {
                    self.config.q_organisation.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("organisation id row {}", i),
                        self.config.organisation[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;

                    region.assign_advice(
                        || format!("organisation type row {}", i),
                        self.config.organisation[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;

                    region.assign_advice(
                        || format!("organisation name row {}", i),
                        self.config.organisation[2],
                        i,
                        || Value::known(F::from(row[2])),
                    )?;
                }
                for (i, row) in organisation_isLocatedIn_place.iter().enumerate() {
                    self.config
                        .q_org_located
                        .enable(&mut region, i + person_table.len())?;

                    region.assign_advice(
                        || format!("org_location org_id row {}", i),
                        self.config.organisation_isLocatedIn_place[0],
                        i + person_table.len(),
                        || Value::known(F::from(row[0])),
                    )?;

                    region.assign_advice(
                        || format!("org_location place_id row {}", i),
                        self.config.organisation_isLocatedIn_place[1],
                        i + person_table.len(),
                        || Value::known(F::from(row[1])),
                    )?;
                }
                for (i, row) in expanded_top_universities_data.iter().enumerate() {
                    self.config.q_top_universities.enable(&mut region, i)?;

                    for j in 0..6 {
                        region.assign_advice(
                            || format!("top_university col {} row {}", j, i),
                            self.config.top_universities[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }
                }

                for (i, row) in expanded_top_companies_data.iter().enumerate() {
                    self.config.q_top_companies.enable(&mut region, i)?;

                    for j in 0..6 {
                        region.assign_advice(
                            || format!("top_company col {} row {}", j, i),
                            self.config.top_companies[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }
                }

                if top20_candidates.len() == 20 {
                    let last_top20_idx = 19;
                    let last_top20 = &top20_candidates[last_top20_idx];

                    for (i, (cand_id, cand_lastname, cand_dist)) in
                        remaining_candidates.iter().enumerate()
                    {
                        self.config.q_candidate_check.enable(&mut region, i)?;

                        region.assign_advice(
                            || format!("candidate_id[{}]", i),
                            self.config.candidate_record[0],
                            i,
                            || Value::known(F::from(*cand_id)),
                        )?;

                        region.assign_advice(
                            || format!("candidate_lastname[{}]", i),
                            self.config.candidate_record[1],
                            i,
                            || Value::known(F::from(*cand_lastname)),
                        )?;

                        region.assign_advice(
                            || format!("candidate_dist[{}]", i),
                            self.config.candidate_record[2],
                            i,
                            || Value::known(F::from(*cand_dist)),
                        )?;

                        candidate_vs_last_dist_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(last_top20.2)],
                                &[F::from(*cand_dist)],
                            )
                            .unwrap();

                        if *cand_dist == last_top20.2 {
                            region.assign_advice(
                                || format!("candvslast_dist_flag[{}]", i),
                                self.config.candvslast_dist_flag,
                                i,
                                || Value::known(F::from(1u64)),
                            )?;
                        } else {
                            region.assign_advice(
                                || format!("candvslast_dist_flag[{}]", i),
                                self.config.candvslast_dist_flag,
                                i,
                                || Value::known(F::from(0u64)),
                            )?;
                        }

                        candvslast_dist_chip
                            .assign(
                                &mut region,
                                i,
                                Value::known(F::from(last_top20.2) - F::from(*cand_dist)),
                            )
                            .unwrap();

                        candidate_vs_last_lastname_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(last_top20.1)],
                                &[F::from(*cand_lastname)],
                            )
                            .unwrap();

                        if *cand_lastname == last_top20.1 {
                            region.assign_advice(
                                || format!("candvslast_lastname_flag[{}]", i),
                                self.config.candvslast_lastname_flag,
                                i,
                                || Value::known(F::from(1u64)),
                            )?;
                        } else {
                            region.assign_advice(
                                || format!("candvslast_lastname_flag[{}]", i),
                                self.config.candvslast_lastname_flag,
                                i,
                                || Value::known(F::from(0u64)),
                            )?;
                        }

                        candvslast_lastname_chip
                            .assign(
                                &mut region,
                                i,
                                Value::known(F::from(last_top20.1) - F::from(*cand_lastname)),
                            )
                            .unwrap();

                        candidate_vs_last_id_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(last_top20.0)],
                                &[F::from(*cand_id)],
                            )
                            .unwrap();
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

pub struct MyCircuit<F> {
    pub person: Vec<Vec<u64>>,
    pub person_knows_person: Vec<Vec<u64>>,
    pub person_id: u64,
    pub person_firstname: u64,
    pub person_speaks_language: Vec<Vec<u64>>,
    pub person_email_emailaddress: Vec<Vec<u64>>,
    pub person_isLocatedIn_place: Vec<Vec<u64>>,
    pub place: Vec<Vec<u64>>,
    pub person_studyAt_organisation: Vec<Vec<u64>>,
    pub person_workAt_organisation: Vec<Vec<u64>>,
    pub organisation: Vec<Vec<u64>>,
    pub organisation_isLocatedIn_place: Vec<Vec<u64>>,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Default::default(),
            person_id: Default::default(),
            person_firstname: Default::default(),
            person_speaks_language: Default::default(),
            person_email_emailaddress: Default::default(),
            person_isLocatedIn_place: Default::default(),
            place: Default::default(),
            person_studyAt_organisation: Default::default(),
            person_workAt_organisation: Default::default(),
            organisation: Default::default(),
            organisation_isLocatedIn_place: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord + std::hash::Hash> Circuit<F> for MyCircuit<F> {
    type Config = ic1CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ic1Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip = ic1Chip::construct(config.clone());

        chip.assign(
            &mut layouter.namespace(|| "Assign"),
            self.person.clone(),
            self.person_knows_person.clone(),
            self.person_id,
            self.person_firstname,
            self.person_speaks_language.clone(),
            self.person_email_emailaddress.clone(),
            self.person_isLocatedIn_place.clone(),
            self.place.clone(),
            self.person_studyAt_organisation.clone(),
            self.person_workAt_organisation.clone(),
            self.organisation.clone(),
            self.organisation_isLocatedIn_place.clone(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::time::Instant;

     #[test]
    fn test_is1_circuit() {
        let k = 16;

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let relation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let email_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_email_emailaddress_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let language_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_speaks_language_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let location_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_isLocatedIn_place_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let place_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/place_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let studyat_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_studyAt_organisation_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let workat_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_workAt_organisation_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let organisation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/organisation_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let org_location_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/organisation_isLocatedIn_place_0_0.csv",
            '|',
        ).expect("Failed to read data");

        let mut person_table = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                row[0].parse::<u64>().expect("invalid ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[2]),
                if row[3] == "male" { 1 } else { 0 },
                parse_date(&row[4]),
                parse_datetime(&row[5]),
                ipv4_to_u64(&row[6]),
                string_to_u64(&row[7]),
            ];
            person_table.push(person_row);
        }

        let mut person_knows_person = Vec::new();
        for (_, row) in relation_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            person_knows_person.push(r_row);
        }

        let mut person_speaks_language = Vec::new();
        for (_, row) in language_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
            ];
            person_speaks_language.push(r_row);
        }

        let mut person_email_emailaddress = Vec::new();
        for (_, row) in email_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
            ];
            person_email_emailaddress.push(r_row);
        }

        let mut person_isLocatedIn_place = Vec::new();
        for (_, row) in location_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                row[1].parse::<u64>().expect("invalid Place ID"),
            ];
            person_isLocatedIn_place.push(r_row);
        }

        let mut place = Vec::new();
        for (_, row) in place_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Place ID"),
                string_to_u64(&row[1]),
            ];
            place.push(r_row);
        }

        let mut person_studyAt_organisation = Vec::new();
        for (_, row) in studyat_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                row[1].parse::<u64>().expect("invalid organisation ID"),
                row[2].parse::<u64>().expect("invalid ClassYear"),
            ];
            person_studyAt_organisation.push(r_row);
        }

        let mut person_workAt_organisation = Vec::new();
        for (_, row) in workat_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                row[1].parse::<u64>().expect("invalid organisation ID"),
                row[2].parse::<u64>().expect("invalid workfrom"),
            ];
            person_workAt_organisation.push(r_row);
        }

        // id | type | name
        let mut organisation = Vec::new();
        for (_, row) in organisation_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                if row[1] == "company" { 1 } else { 0 },
                string_to_u64(&row[2]),
            ];
            organisation.push(r_row);
        }
        let mut organisation_isLocatedIn_place = Vec::new();
        for (_, row) in org_location_data.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Organisation ID"),
                row[1].parse::<u64>().expect("invalid Place ID"),
            ];
            organisation_isLocatedIn_place.push(r_row);
        }

        println!("person:{:?}", person_table.len());
        println!("person_knows_person.len:{:?}", person_knows_person.len());

        let test_person_id: u64 = 2199023264045;
        let test_person_firstname = string_to_u64("Mike");

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_knows_person,
            person_id: test_person_id,
            person_firstname: test_person_firstname,
            _marker: PhantomData,
            person_speaks_language,
            person_email_emailaddress,
            person_isLocatedIn_place,
            place,
            person_studyAt_organisation,
            person_workAt_organisation,
            organisation,
            organisation_isLocatedIn_place,
        };

        let public_input = vec![Fr::from(1)];
        let start = Instant::now();
        let prover = MockProver::run(k, &circuit, vec![public_input]).expect("MockProver fail");
        println!("Proving time: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("verification failed{:?}", e);
            }
        }
    }
}
