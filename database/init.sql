-- Initialize PostgreSQL database with PostGIS extension
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;

-- Create additional indexes for performance
-- These will be created after Django migrations run

-- Create custom functions for land plot calculations
CREATE OR REPLACE FUNCTION calculate_area_hectares(geometry geometry)
RETURNS decimal(12,2) AS $$
BEGIN
    RETURN ST_Area(geometry) / 10000;
END;
$$ LANGUAGE plpgsql;

-- Create function to check if point is within land plot
CREATE OR REPLACE FUNCTION is_point_within_land_plot(point geometry, land_plot_id uuid)
RETURNS boolean AS $$
BEGIN
    RETURN EXISTS(
        SELECT 1 FROM land_plots 
        WHERE id = land_plot_id AND ST_Contains(geometry, point)
    );
END;
$$ LANGUAGE plpgsql;

-- Create function to get nearby land plots
CREATE OR REPLACE FUNCTION get_nearby_land_plots(center_point geometry, distance_km integer)
RETURNS TABLE(id uuid, cadastral_number varchar, area decimal, distance decimal) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        lp.id,
        lp.cadastral_number,
        lp.area,
        ST_Distance(lp.centroid, center_point) / 1000 as distance_km
    FROM land_plots lp
    WHERE ST_DWithin(lp.centroid, center_point, distance_km * 1000)
    ORDER BY distance_km;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update centroid when geometry changes
CREATE OR REPLACE FUNCTION update_land_plot_centroid()
RETURNS trigger AS $$
BEGIN
    NEW.centroid = ST_Centroid(NEW.geometry);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger (will be attached after table creation)
-- CREATE TRIGGER trigger_update_land_plot_centroid
--     BEFORE INSERT OR UPDATE ON land_plots
--     FOR EACH ROW EXECUTE FUNCTION update_land_plot_centroid();

-- Create view for land plot statistics
CREATE OR REPLACE VIEW land_plot_statistics AS
SELECT 
    r.name as region_name,
    COUNT(lp.id) as total_plots,
    SUM(lp.area) as total_area,
    AVG(lp.area) as average_area,
    COUNT(CASE WHEN lp.is_verified = true THEN 1 END) as verified_plots,
    COUNT(CASE WHEN lp.is_active = true THEN 1 END) as active_plots
FROM land_plots lp
JOIN regions r ON lp.region_id = r.id
GROUP BY r.id, r.name;

-- Create view for contract statistics
CREATE OR REPLACE VIEW contract_statistics AS
SELECT 
    DATE_TRUNC('month', c.created_at) as month,
    COUNT(c.id) as total_contracts,
    COUNT(CASE WHEN c.status = 'signed' THEN 1 END) as signed_contracts,
    COUNT(CASE WHEN c.status = 'pending' THEN 1 END) as pending_contracts,
    COUNT(CASE WHEN c.status = 'cancelled' THEN 1 END) as cancelled_contracts,
    AVG(c.total_amount) as average_amount
FROM contracts c
GROUP BY DATE_TRUNC('month', c.created_at)
ORDER BY month DESC;

-- Create function to validate cadastral number format
CREATE OR REPLACE FUNCTION is_valid_cadastral_number(cadastral_number varchar)
RETURNS boolean AS $$
BEGIN
    RETURN cadastral_number ~ '^\d{2}:\d{2}:\d{6,7}:\d{1,6}$';
END;
$$ LANGUAGE plpgsql;

-- Create function to generate contract number
CREATE OR REPLACE FUNCTION generate_contract_number()
RETURNS varchar AS $$
DECLARE
    contract_number varchar;
    date_part varchar;
    sequence_part integer;
BEGIN
    date_part := TO_CHAR(NOW(), 'YYYYMM');
    
    SELECT COALESCE(MAX(CAST(SUBSTRING(contract_number FROM '\d+$') AS integer)), 0) + 1
    INTO sequence_part
    FROM contracts
    WHERE contract_number LIKE 'К-' || date_part || '-%';
    
    contract_number := 'К-' || date_part || '-' || LPAD(sequence_part::text, 4, '0');
    
    RETURN contract_number;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for spatial queries
-- CREATE INDEX idx_land_plots_geometry ON land_plots USING GIST(geometry);
-- CREATE INDEX idx_land_plots_centroid ON land_plots USING GIST(centroid);

-- Create indexes for performance
-- CREATE INDEX idx_land_plots_cadastral_number ON land_plots(cadastral_number);
-- CREATE INDEX idx_land_plots_region ON land_plots(region_id);
-- CREATE INDEX idx_land_plots_category ON land_plots(category_id);
-- CREATE INDEX idx_land_plots_is_verified ON land_plots(is_verified);
-- CREATE INDEX idx_contracts_status ON contracts(status);
-- CREATE INDEX idx_contracts_created_at ON contracts(created_at);
-- CREATE INDEX idx_contract_documents_contract ON contract_documents(contract_id);

-- Create user-defined types for contract statuses
CREATE TYPE contract_status_enum AS ENUM (
    'draft',
    'pending_signature',
    'signed',
    'registered',
    'cancelled',
    'expired'
);

-- Create user-defined types for land ownership types
CREATE TYPE ownership_type_enum AS ENUM (
    'state',
    'municipal',
    'private',
    'shared'
);

-- Grant permissions to the database user
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;